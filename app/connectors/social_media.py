"""
Social Media Content Connector.

This module provides connectors for social media platforms including:
- Twitter/X API
- Reddit API
- LinkedIn API
- Generic social media API support
"""

import json
import hashlib
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from urllib.parse import urlencode

from app.connectors.base import (
    ContentConnector,
    ContentItem,
    ContentData,
    ValidationResult,
    ConnectorConfig,
    ConnectorType,
    ContentType,
    ValidationStatus
)
from app.utils.logging import get_logger

logger = get_logger("social_media_connector")


class TwitterConnector(ContentConnector):
    """Connector for Twitter/X API."""

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.api_base_url = "https://api.twitter.com/2"
        self.tweet_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = 300  # 5 minutes

    async def discover(self, source_config: Dict[str, Any]) -> List[ContentItem]:
        """Discover content from Twitter/X."""
        query_type = source_config.get("query_type", "search")
        query_params = source_config.get("query_params", {})

        if query_type == "search":
            return await self._search_tweets(query_params)
        elif query_type == "user_timeline":
            return await self._get_user_timeline(query_params)
        elif query_type == "bookmarks":
            return await self._get_bookmarks(query_params)
        else:
            raise ValueError(f"Unsupported query type: {query_type}")

    async def _search_tweets(self, params: Dict[str, Any]) -> List[ContentItem]:
        """Search for tweets."""
        query = params.get("query", "")
        max_results = params.get("max_results", 10)
        since_id = params.get("since_id")

        if not query:
            raise ValueError("Search query is required")

        endpoint = f"{self.api_base_url}/tweets/search/recent"
        query_params = {
            "query": query,
            "max_results": min(max_results, 100),
            "tweet.fields": "created_at,public_metrics,author_id,context_annotations,entities",
            "user.fields": "username,name,verified",
            "expansions": "author_id"
        }

        if since_id:
            query_params["since_id"] = since_id

        response = await self._make_authenticated_request("GET", endpoint, params=query_params)

        if response.status_code != 200:
            raise Exception(f"Twitter API error: HTTP {response.status_code}")

        data = response.json_data
        return self._parse_tweets(data, "search")

    async def _get_user_timeline(self, params: Dict[str, Any]) -> List[ContentItem]:
        """Get user timeline."""
        username = params.get("username")
        user_id = params.get("user_id")
        max_results = params.get("max_results", 10)

        if not username and not user_id:
            raise ValueError("Username or user_id is required")

        # First get user ID if username provided
        if username and not user_id:
            user_data = await self._get_user_by_username(username)
            user_id = user_data["id"]

        endpoint = f"{self.api_base_url}/users/{user_id}/tweets"
        query_params = {
            "max_results": min(max_results, 100),
            "tweet.fields": "created_at,public_metrics,author_id,context_annotations,entities",
            "user.fields": "username,name,verified",
            "expansions": "author_id"
        }

        response = await self._make_authenticated_request("GET", endpoint, params=query_params)

        if response.status_code != 200:
            raise Exception(f"Twitter API error: HTTP {response.status_code}")

        data = response.json_data
        return self._parse_tweets(data, "timeline")

    async def _get_bookmarks(self, params: Dict[str, Any]) -> List[ContentItem]:
        """Get user bookmarks."""
        user_id = params.get("user_id")
        max_results = params.get("max_results", 10)

        if not user_id:
            # Try to get current user ID
            user_id = await self._get_current_user_id()

        endpoint = f"{self.api_base_url}/users/{user_id}/bookmarks"
        query_params = {
            "max_results": min(max_results, 100),
            "tweet.fields": "created_at,public_metrics,author_id,context_annotations,entities",
            "user.fields": "username,name,verified",
            "expansions": "author_id"
        }

        response = await self._make_authenticated_request("GET", endpoint, params=query_params)

        if response.status_code != 200:
            raise Exception(f"Twitter API error: HTTP {response.status_code}")

        data = response.json_data
        return self._parse_tweets(data, "bookmarks")

    async def _get_user_by_username(self, username: str) -> Dict[str, Any]:
        """Get user data by username."""
        endpoint = f"{self.api_base_url}/users/by/username/{username}"
        query_params = {"user.fields": "id,name,username,verified"}

        response = await self._make_authenticated_request("GET", endpoint, params=query_params)

        if response.status_code != 200:
            raise Exception(f"Failed to get user data: HTTP {response.status_code}")

        return response.json_data["data"]

    async def _get_current_user_id(self) -> str:
        """Get current authenticated user ID."""
        endpoint = f"{self.api_base_url}/users/me"
        response = await self._make_authenticated_request("GET", endpoint)

        if response.status_code != 200:
            raise Exception(f"Failed to get current user: HTTP {response.status_code}")

        return response.json_data["data"]["id"]

    async def _make_authenticated_request(self, method: str, url: str, params: Optional[Dict[str, Any]] = None, data: Optional[Dict[str, Any]] = None) -> Any:
        """Make authenticated request to Twitter API."""
        headers = {
            "Authorization": f"Bearer {self.config.credentials.get('bearer_token', '')}",
            "Content-Type": "application/json"
        }

        return await self.http_client.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json_data=data,
            timeout=30.0
        )

    def _parse_tweets(self, data: Dict[str, Any], source_type: str) -> List[ContentItem]:
        """Parse Twitter API response into ContentItems."""
        items = []

        tweets = data.get("data", [])
        users = {user["id"]: user for user in data.get("includes", {}).get("users", [])}

        for tweet in tweets:
            try:
                author = users.get(tweet.get("author_id", ""))
                author_name = author.get("name", "Unknown") if author else "Unknown"
                author_username = author.get("username", "") if author else ""

                tweet_id = tweet["id"]
                created_at = datetime.fromisoformat(tweet["created_at"].replace('Z', '+00:00'))
                text = tweet["text"]

                # Create tweet URL
                tweet_url = f"https://twitter.com/{author_username}/status/{tweet_id}"

                # Extract entities
                entities = tweet.get("entities", {})
                hashtags = [tag["tag"] for tag in entities.get("hashtags", [])]
                mentions = [mention["username"] for mention in entities.get("mentions", [])]

                # Get metrics
                metrics = tweet.get("public_metrics", {})
                likes = metrics.get("like_count", 0)
                retweets = metrics.get("retweet_count", 0)
                replies = metrics.get("reply_count", 0)

                item = ContentItem(
                    id=tweet_id,
                    source=f"twitter_{source_type}",
                    connector_type=ConnectorType.SOCIAL_MEDIA,
                    content_type=ContentType.TEXT,
                    title=f"Tweet by @{author_username}",
                    description=text,
                    url=tweet_url,
                    metadata={
                        "platform": "twitter",
                        "author_name": author_name,
                        "author_username": author_username,
                        "author_id": tweet.get("author_id"),
                        "likes": likes,
                        "retweets": retweets,
                        "replies": replies,
                        "hashtags": hashtags,
                        "mentions": mentions,
                        "context_annotations": tweet.get("context_annotations", []),
                        "source_type": source_type
                    },
                    last_modified=created_at,
                    tags=["twitter", "tweet", "social_media"] + hashtags
                )

                items.append(item)

            except Exception as e:
                self.logger.error(f"Failed to parse tweet {tweet.get('id', 'unknown')}: {e}")
                continue

        return items

    async def fetch(self, content_ref: Union[str, ContentItem]) -> ContentData:
        """Fetch tweet content."""
        if isinstance(content_ref, str):
            tweet_id = content_ref
        else:
            tweet_id = content_ref.id

        start_time = datetime.now()

        # Get single tweet
        endpoint = f"{self.api_base_url}/tweets/{tweet_id}"
        query_params = {
            "tweet.fields": "created_at,public_metrics,author_id,context_annotations,entities",
            "user.fields": "username,name,verified",
            "expansions": "author_id"
        }

        response = await self._make_authenticated_request("GET", endpoint, params=query_params)

        if response.status_code != 200:
            raise Exception(f"Failed to fetch tweet: HTTP {response.status_code}")

        data = response.json_data
        tweet = data["data"]
        users = {user["id"]: user for user in data.get("includes", {}).get("users", [])}

        # Create ContentItem if not provided
        if isinstance(content_ref, str):
            content_ref = self._parse_tweets({"data": [tweet], "includes": {"users": list(users.values())}}, "single")[0]

        processing_time = (datetime.now() - start_time).total_seconds() * 1000

        return ContentData(
            item=content_ref,
            raw_data=json.dumps(tweet).encode('utf-8'),
            text_content=tweet["text"],
            structured_data=tweet,
            metadata={
                "fetched_at": datetime.now().isoformat(),
                "processing_time_ms": processing_time
            },
            processing_time_ms=processing_time
        )

    async def validate(self, content: Union[ContentData, bytes]) -> ValidationResult:
        """Validate Twitter content."""
        if isinstance(content, ContentData):
            structured_data = content.structured_data
            text_content = content.text_content or ""
        else:
            try:
                structured_data = json.loads(content.decode('utf-8'))
                text_content = structured_data.get("text", "")
            except (UnicodeDecodeError, json.JSONDecodeError):
                structured_data = None
                text_content = ""

        errors = []
        warnings = []

        # Check required fields
        if structured_data:
            if "id" not in structured_data:
                errors.append("Missing tweet ID")
            if "text" not in structured_data:
                errors.append("Missing tweet text")
            if "author_id" not in structured_data:
                warnings.append("Missing author ID")

        # Check text content
        if len(text_content.strip()) == 0:
            errors.append("Tweet text is empty")
        elif len(text_content) > 280:
            warnings.append("Tweet text exceeds 280 characters")

        # Check for sensitive content markers
        if structured_data and structured_data.get("possibly_sensitive"):
            warnings.append("Tweet marked as potentially sensitive")

        is_valid = len(errors) == 0
        status = ValidationStatus.VALID if is_valid else ValidationStatus.INVALID
        if warnings and not errors:
            status = ValidationStatus.WARNING

        return ValidationResult(
            is_valid=is_valid,
            status=status,
            message="Twitter content validation completed",
            errors=errors,
            warnings=warnings,
            metadata={
                "has_structured_data": structured_data is not None,
                "text_length": len(text_content),
                "has_author": bool(structured_data and structured_data.get("author_id")),
                "possibly_sensitive": structured_data.get("possibly_sensitive", False) if structured_data else False
            }
        )

    def get_capabilities(self) -> Dict[str, Any]:
        """Get Twitter connector capabilities."""
        capabilities = super().get_capabilities()
        capabilities.update({
            "supported_content_types": ["text"],
            "supported_operations": ["search", "timeline", "bookmarks", "single_tweet"],
            "features": ["real_time_updates", "rate_limiting", "authentication"],
            "authentication_methods": ["bearer_token", "oauth2"],
            "rate_limiting": True,
            "retry_support": True,
            "batch_operations": False,
            "real_time_updates": True
        })
        return capabilities


class RedditConnector(ContentConnector):
    """Connector for Reddit API."""

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.api_base_url = "https://www.reddit.com"
        self.oauth_url = "https://oauth.reddit.com"
        self.post_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = 600  # 10 minutes

    async def discover(self, source_config: Dict[str, Any]) -> List[ContentItem]:
        """Discover content from Reddit."""
        content_type = source_config.get("content_type", "posts")
        subreddit = source_config.get("subreddit")
        query = source_config.get("query")
        sort = source_config.get("sort", "hot")
        limit = source_config.get("limit", 10)

        if content_type == "posts":
            if subreddit:
                return await self._get_subreddit_posts(subreddit, sort, limit)
            elif query:
                return await self._search_posts(query, sort, limit)
            else:
                raise ValueError("Subreddit or query is required for posts")
        elif content_type == "comments":
            if not subreddit:
                raise ValueError("Subreddit is required for comments")
            return await self._get_subreddit_comments(subreddit, limit)
        else:
            raise ValueError(f"Unsupported content type: {content_type}")

    async def _get_subreddit_posts(self, subreddit: str, sort: str, limit: int) -> List[ContentItem]:
        """Get posts from a subreddit."""
        endpoint = f"{self.api_base_url}/r/{subreddit}/{sort}/.json"
        params = {"limit": min(limit, 100)}

        response = await self._make_request("GET", endpoint, params=params)

        if response.status_code != 200:
            raise Exception(f"Reddit API error: HTTP {response.status_code}")

        data = response.json_data
        return self._parse_reddit_posts(data, f"r/{subreddit}")

    async def _search_posts(self, query: str, sort: str, limit: int) -> List[ContentItem]:
        """Search for posts."""
        endpoint = f"{self.api_base_url}/search/.json"
        params = {
            "q": query,
            "sort": sort,
            "limit": min(limit, 100),
            "type": "link"
        }

        response = await self._make_request("GET", endpoint, params=params)

        if response.status_code != 200:
            raise Exception(f"Reddit API error: HTTP {response.status_code}")

        data = response.json_data
        return self._parse_reddit_posts(data, f"search:{query}")

    async def _get_subreddit_comments(self, subreddit: str, limit: int) -> List[ContentItem]:
        """Get comments from a subreddit."""
        endpoint = f"{self.api_base_url}/r/{subreddit}/comments/.json"
        params = {"limit": min(limit, 100)}

        response = await self._make_request("GET", endpoint, params=params)

        if response.status_code != 200:
            raise Exception(f"Reddit API error: HTTP {response.status_code}")

        data = response.json_data
        return self._parse_reddit_comments(data, f"r/{subreddit}")

    async def _make_request(self, method: str, url: str, params: Optional[Dict[str, Any]] = None, data: Optional[Dict[str, Any]] = None) -> Any:
        """Make request to Reddit API."""
        headers = {
            "User-Agent": self.config.credentials.get("user_agent", "Agentic-Backend/1.0")
        }

        # Add OAuth token if available
        if "access_token" in self.config.credentials:
            headers["Authorization"] = f"Bearer {self.config.credentials['access_token']}"

        return await self.http_client.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json_data=data,
            timeout=30.0
        )

    def _parse_reddit_posts(self, data: Dict[str, Any], source: str) -> List[ContentItem]:
        """Parse Reddit posts."""
        items = []

        posts = data.get("data", {}).get("children", [])

        for post in posts:
            try:
                post_data = post["data"]
                post_id = post_data["id"]
                created_utc = datetime.fromtimestamp(post_data["created_utc"])

                # Create Reddit URL
                permalink = post_data.get("permalink", "")
                url = f"https://www.reddit.com{permalink}" if permalink else None

                # Get selftext or URL
                content = post_data.get("selftext", "")
                if not content and post_data.get("url"):
                    content = f"Link: {post_data['url']}"

                item = ContentItem(
                    id=f"t3_{post_id}",
                    source=source,
                    connector_type=ConnectorType.SOCIAL_MEDIA,
                    content_type=ContentType.TEXT,
                    title=post_data.get("title", ""),
                    description=content,
                    url=url,
                    metadata={
                        "platform": "reddit",
                        "subreddit": post_data.get("subreddit"),
                        "author": post_data.get("author"),
                        "score": post_data.get("score", 0),
                        "upvote_ratio": post_data.get("upvote_ratio", 0),
                        "num_comments": post_data.get("num_comments", 0),
                        "post_type": "self" if post_data.get("is_self") else "link",
                        "domain": post_data.get("domain"),
                        "stickied": post_data.get("stickied", False),
                        "over_18": post_data.get("over_18", False)
                    },
                    last_modified=created_utc,
                    tags=["reddit", "post", "social_media", post_data.get("subreddit", "")]
                )

                items.append(item)

            except Exception as e:
                self.logger.error(f"Failed to parse Reddit post {post_data.get('id', 'unknown')}: {e}")
                continue

        return items

    def _parse_reddit_comments(self, data: Dict[str, Any], source: str) -> List[ContentItem]:
        """Parse Reddit comments."""
        items = []

        # Reddit returns posts and comments in separate arrays
        comments_data = data[1] if len(data) > 1 else {"data": {"children": []}}
        comments = comments_data.get("data", {}).get("children", [])

        for comment in comments:
            try:
                comment_data = comment["data"]
                comment_id = comment_data["id"]
                created_utc = datetime.fromtimestamp(comment_data["created_utc"])

                # Create comment URL
                permalink = comment_data.get("permalink", "")
                url = f"https://www.reddit.com{permalink}" if permalink else None

                item = ContentItem(
                    id=f"t1_{comment_id}",
                    source=source,
                    connector_type=ConnectorType.SOCIAL_MEDIA,
                    content_type=ContentType.TEXT,
                    title=f"Comment by {comment_data.get('author', 'Unknown')}",
                    description=comment_data.get("body", ""),
                    url=url,
                    metadata={
                        "platform": "reddit",
                        "subreddit": comment_data.get("subreddit"),
                        "author": comment_data.get("author"),
                        "score": comment_data.get("score", 0),
                        "parent_id": comment_data.get("parent_id"),
                        "link_id": comment_data.get("link_id"),
                        "depth": comment_data.get("depth", 0),
                        "controversiality": comment_data.get("controversiality", 0),
                        "stickied": comment_data.get("stickied", False)
                    },
                    last_modified=created_utc,
                    tags=["reddit", "comment", "social_media", comment_data.get("subreddit", "")]
                )

                items.append(item)

            except Exception as e:
                self.logger.error(f"Failed to parse Reddit comment {comment_data.get('id', 'unknown')}: {e}")
                continue

        return items

    async def fetch(self, content_ref: Union[str, ContentItem]) -> ContentData:
        """Fetch Reddit content."""
        if isinstance(content_ref, str):
            # Assume it's a Reddit ID
            reddit_id = content_ref
        else:
            reddit_id = content_ref.id

        start_time = datetime.now()

        # Reddit API doesn't have a direct endpoint for single items
        # We'll construct the URL and fetch the page
        if reddit_id.startswith("t3_"):
            # Post
            post_id = reddit_id[3:]
            url = f"{self.api_base_url}/comments/{post_id}/.json"
        elif reddit_id.startswith("t1_"):
            # Comment - need to get the parent post
            comment_id = reddit_id[3:]
            url = f"{self.api_base_url}/api/info/.json?id=t1_{comment_id}"
        else:
            raise ValueError(f"Unsupported Reddit ID format: {reddit_id}")

        response = await self._make_request("GET", url)

        if response.status_code != 200:
            raise Exception(f"Failed to fetch Reddit content: HTTP {response.status_code}")

        processing_time = (datetime.now() - start_time).total_seconds() * 1000

        return ContentData(
            item=content_ref if isinstance(content_ref, ContentItem) else None,
            raw_data=response.content,
            text_content=response.text,
            structured_data=response.json_data,
            metadata={
                "fetched_at": datetime.now().isoformat(),
                "processing_time_ms": processing_time
            },
            processing_time_ms=processing_time
        )

    async def validate(self, content: Union[ContentData, bytes]) -> ValidationResult:
        """Validate Reddit content."""
        if isinstance(content, ContentData):
            structured_data = content.structured_data
            text_content = content.text_content or ""
        else:
            try:
                structured_data = json.loads(content.decode('utf-8'))
                text_content = ""
                if isinstance(structured_data, list) and len(structured_data) > 0:
                    first_item = structured_data[0]
                    if isinstance(first_item, dict) and "data" in first_item:
                        text_content = first_item["data"].get("selftext", "")
            except (UnicodeDecodeError, json.JSONDecodeError, KeyError):
                structured_data = None
                text_content = ""

        errors = []
        warnings = []

        # Check Reddit-specific validation
        if structured_data:
            if isinstance(structured_data, list) and len(structured_data) > 0:
                first_item = structured_data[0]
                if isinstance(first_item, dict) and "data" in first_item:
                    item_data = first_item["data"]

                    # Check for removed/deleted content
                    if item_data.get("removed_by_category"):
                        warnings.append("Content has been removed by moderators")
                    if item_data.get("deleted"):
                        errors.append("Content has been deleted")

                    # Check for NSFW content
                    if item_data.get("over_18"):
                        warnings.append("Content marked as NSFW")

        # Check text content
        if len(text_content.strip()) == 0:
            warnings.append("No text content found")

        is_valid = len(errors) == 0
        status = ValidationStatus.VALID if is_valid else ValidationStatus.INVALID
        if warnings and not errors:
            status = ValidationStatus.WARNING

        return ValidationResult(
            is_valid=is_valid,
            status=status,
            message="Reddit content validation completed",
            errors=errors,
            warnings=warnings,
            metadata={
                "has_structured_data": structured_data is not None,
                "text_length": len(text_content),
                "is_deleted": any(item.get("data", {}).get("deleted") for item in (structured_data or []) if isinstance(item, dict)),
                "is_removed": any(item.get("data", {}).get("removed_by_category") for item in (structured_data or []) if isinstance(item, dict))
            }
        )

    def get_capabilities(self) -> Dict[str, Any]:
        """Get Reddit connector capabilities."""
        capabilities = super().get_capabilities()
        capabilities.update({
            "supported_content_types": ["text"],
            "supported_operations": ["subreddit_posts", "search", "comments"],
            "features": ["rate_limiting", "authentication", "content_filtering"],
            "authentication_methods": ["none", "oauth2", "script_auth"],
            "rate_limiting": True,
            "retry_support": True,
            "batch_operations": False,
            "real_time_updates": False
        })
        return capabilities


class LinkedInConnector(ContentConnector):
    """Connector for LinkedIn API."""

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.api_base_url = "https://api.linkedin.com/v2"
        self.post_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = 300  # 5 minutes

    async def discover(self, source_config: Dict[str, Any]) -> List[ContentItem]:
        """Discover content from LinkedIn."""
        content_type = source_config.get("content_type", "posts")
        profile_id = source_config.get("profile_id")
        organization_id = source_config.get("organization_id")
        limit = source_config.get("limit", 10)

        if content_type == "posts":
            if profile_id:
                return await self._get_profile_posts(profile_id, limit)
            elif organization_id:
                return await self._get_organization_posts(organization_id, limit)
            else:
                raise ValueError("Profile ID or organization ID is required for posts")
        elif content_type == "feed":
            return await self._get_feed(limit)
        else:
            raise ValueError(f"Unsupported content type: {content_type}")

    async def _get_profile_posts(self, profile_id: str, limit: int) -> List[ContentItem]:
        """Get posts from a user profile."""
        endpoint = f"{self.api_base_url}/people/{profile_id}/posts"
        params = {
            "count": min(limit, 50),
            "projection": "(id,author,commentary,content,lifecycleState,created,modified,visibility,lastModified)"
        }

        response = await self._make_authenticated_request("GET", endpoint, params=params)

        if response.status_code != 200:
            raise Exception(f"LinkedIn API error: HTTP {response.status_code}")

        data = response.json_data
        return self._parse_linkedin_posts(data, f"profile/{profile_id}")

    async def _get_organization_posts(self, organization_id: str, limit: int) -> List[ContentItem]:
        """Get posts from an organization."""
        endpoint = f"{self.api_base_url}/organizations/{organization_id}/posts"
        params = {
            "count": min(limit, 50),
            "projection": "(id,author,commentary,content,lifecycleState,created,modified,visibility,lastModified)"
        }

        response = await self._make_authenticated_request("GET", endpoint, params=params)

        if response.status_code != 200:
            raise Exception(f"LinkedIn API error: HTTP {response.status_code}")

        data = response.json_data
        return self._parse_linkedin_posts(data, f"organization/{organization_id}")

    async def _get_feed(self, limit: int) -> List[ContentItem]:
        """Get user's feed."""
        endpoint = f"{self.api_base_url}/feeds"
        params = {
            "count": min(limit, 50),
            "projection": "(id,actor,commentary,content,lifecycleState,created,modified,visibility,lastModified)"
        }

        response = await self._make_authenticated_request("GET", endpoint, params=params)

        if response.status_code != 200:
            raise Exception(f"LinkedIn API error: HTTP {response.status_code}")

        data = response.json_data
        return self._parse_linkedin_posts(data, "feed")

    async def _make_authenticated_request(self, method: str, url: str, params: Optional[Dict[str, Any]] = None, data: Optional[Dict[str, Any]] = None) -> Any:
        """Make authenticated request to LinkedIn API."""
        headers = {
            "Authorization": f"Bearer {self.config.credentials.get('access_token', '')}",
            "X-Restli-Protocol-Version": "2.0.0",
            "Content-Type": "application/json"
        }

        return await self.http_client.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json_data=data,
            timeout=30.0
        )

    def _parse_linkedin_posts(self, data: Dict[str, Any], source: str) -> List[ContentItem]:
        """Parse LinkedIn posts."""
        items = []

        posts = data.get("elements", [])

        for post in posts:
            try:
                post_id = post["id"]
                created_time = datetime.fromtimestamp(post["created"]["time"] / 1000)
                modified_time = datetime.fromtimestamp(post["lastModified"]["time"] / 1000)

                # Extract author information
                author = post.get("author", {})
                author_name = author.get("name", "Unknown")
                author_id = author.get("id", "")

                # Extract content
                commentary = post.get("commentary", "")
                content = post.get("content", {})

                # Build description
                description = commentary
                if content.get("contentEntities"):
                    for entity in content["contentEntities"]:
                        if entity.get("entity"):
                            description += f"\n{entity['entity']}"

                # Create LinkedIn URL (approximate)
                url = f"https://www.linkedin.com/feed/update/{post_id}/"

                item = ContentItem(
                    id=post_id,
                    source=source,
                    connector_type=ConnectorType.SOCIAL_MEDIA,
                    content_type=ContentType.TEXT,
                    title=f"Post by {author_name}",
                    description=description,
                    url=url,
                    metadata={
                        "platform": "linkedin",
                        "author_name": author_name,
                        "author_id": author_id,
                        "lifecycle_state": post.get("lifecycleState"),
                        "visibility": post.get("visibility", {}).get("code"),
                        "content_type": content.get("type"),
                        "has_media": bool(content.get("contentEntities")),
                        "commentary_length": len(commentary)
                    },
                    last_modified=modified_time,
                    tags=["linkedin", "post", "social_media", "professional"]
                )

                items.append(item)

            except Exception as e:
                self.logger.error(f"Failed to parse LinkedIn post {post.get('id', 'unknown')}: {e}")
                continue

        return items

    async def fetch(self, content_ref: Union[str, ContentItem]) -> ContentData:
        """Fetch LinkedIn content."""
        if isinstance(content_ref, str):
            post_id = content_ref
        else:
            post_id = content_ref.id

        start_time = datetime.now()

        # Get single post
        endpoint = f"{self.api_base_url}/posts/{post_id}"
        params = {
            "projection": "(id,author,commentary,content,lifecycleState,created,modified,visibility,lastModified)"
        }

        response = await self._make_authenticated_request("GET", endpoint, params=params)

        if response.status_code != 200:
            raise Exception(f"Failed to fetch LinkedIn post: HTTP {response.status_code}")

        processing_time = (datetime.now() - start_time).total_seconds() * 1000

        return ContentData(
            item=content_ref if isinstance(content_ref, ContentItem) else None,
            raw_data=response.content,
            text_content=response.text,
            structured_data=response.json_data,
            metadata={
                "fetched_at": datetime.now().isoformat(),
                "processing_time_ms": processing_time
            },
            processing_time_ms=processing_time
        )

    async def validate(self, content: Union[ContentData, bytes]) -> ValidationResult:
        """Validate LinkedIn content."""
        if isinstance(content, ContentData):
            structured_data = content.structured_data
            text_content = content.text_content or ""
        else:
            try:
                structured_data = json.loads(content.decode('utf-8'))
                text_content = structured_data.get("commentary", "")
            except (UnicodeDecodeError, json.JSONDecodeError):
                structured_data = None
                text_content = ""

        errors = []
        warnings = []

        # Check LinkedIn-specific validation
        if structured_data:
            if "id" not in structured_data:
                errors.append("Missing post ID")
            if "author" not in structured_data:
                warnings.append("Missing author information")

            # Check lifecycle state
            lifecycle_state = structured_data.get("lifecycleState")
            if lifecycle_state == "ARCHIVED":
                warnings.append("Post has been archived")
            elif lifecycle_state == "DELETED":
                errors.append("Post has been deleted")

        # Check content
        if len(text_content.strip()) == 0:
            warnings.append("No text content found")

        is_valid = len(errors) == 0
        status = ValidationStatus.VALID if is_valid else ValidationStatus.INVALID
        if warnings and not errors:
            status = ValidationStatus.WARNING

        return ValidationResult(
            is_valid=is_valid,
            status=status,
            message="LinkedIn content validation completed",
            errors=errors,
            warnings=warnings,
            metadata={
                "has_structured_data": structured_data is not None,
                "text_length": len(text_content),
                "lifecycle_state": structured_data.get("lifecycleState") if structured_data else None,
                "has_author": bool(structured_data and structured_data.get("author"))
            }
        )

    def get_capabilities(self) -> Dict[str, Any]:
        """Get LinkedIn connector capabilities."""
        capabilities = super().get_capabilities()
        capabilities.update({
            "supported_content_types": ["text"],
            "supported_operations": ["profile_posts", "organization_posts", "feed"],
            "features": ["authentication", "rate_limiting", "content_filtering"],
            "authentication_methods": ["oauth2"],
            "rate_limiting": True,
            "retry_support": True,
            "batch_operations": False,
            "real_time_updates": False
        })
        return capabilities