"""Campaign management tools for Amazon Ads MCP.

Provides create, update, and list operations for Sponsored Products and
Sponsored Brands campaigns, ad groups, keywords, product ads, targets,
negative keywords, and negative targets.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _asin_expression(asin: str) -> List[Dict[str, str]]:
    """Build a single-ASIN targeting expression (for create endpoints).

    Note: v3 Sponsored Products endpoints — both list and create, for both
    positive targets and negative targets — use UPPER_SNAKE_CASE enum
    values (e.g. ASIN_SAME_AS). Never pass the camelCase form
    (asinSameAs); the API rejects it with HTTP 400.
    """
    return [{"type": "ASIN_SAME_AS", "value": asin}]


# ---------------------------------------------------------------------------
# SP Campaign updates
# ---------------------------------------------------------------------------

async def update_sp_campaigns(
    campaign_id: str,
    name: Optional[str] = None,
    state: Optional[str] = None,
    budget_amount: Optional[float] = None,
    budget_type: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    placement_top_pct: Optional[int] = None,
    placement_product_page_pct: Optional[int] = None,
    placement_rest_of_search_pct: Optional[int] = None,
    bidding_strategy: Optional[str] = None,
) -> dict:
    """Update one Sponsored Products campaign.

    :param campaign_id: Campaign ID to update
    :param name: New campaign name
    :param state: New state (ENABLED, PAUSED). The SP v3 PUT /sp/campaigns
        endpoint rejects ARCHIVED — use archive_sp_campaign instead.
    :param budget_amount: New daily budget amount
    :param budget_type: Budget type (DAILY)
    :param start_date: Start date YYYYMMDD
    :param end_date: End date YYYYMMDD
    :param placement_top_pct: Top of Search placement bid adjustment (0-900)
    :param placement_product_page_pct: Product Page placement bid adjustment (0-900)
    :param placement_rest_of_search_pct: Rest of Search placement bid adjustment (0-900)
    :param bidding_strategy: Bidding strategy (LEGACY_FOR_SALES, AUTO_FOR_SALES, MANUAL, RULE_BASED)

    Placement adjustments are merged: any placement not specified retains its
    current value, requiring a read-modify-write. The Amazon Ads v3 PUT
    /sp/campaigns endpoint replaces the dynamicBidding object wholesale, so
    omitting unchanged placements would silently zero them out.
    """
    from ..utils.http_client import get_authenticated_client

    bidding_fields_set = (
        placement_top_pct is not None
        or placement_product_page_pct is not None
        or placement_rest_of_search_pct is not None
        or bidding_strategy is not None
    )

    for label, value in (
        ("placement_top_pct", placement_top_pct),
        ("placement_product_page_pct", placement_product_page_pct),
        ("placement_rest_of_search_pct", placement_rest_of_search_pct),
    ):
        if value is not None and (value < 0 or value > 900):
            return {
                "success": False,
                "campaign_id": campaign_id,
                "error": f"Invalid {label}: {value} (must be 0-900)",
                "message": f"Invalid placement bidding value for {label}",
            }

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spcampaign.v3+json",
        "Content-Type": "application/vnd.spcampaign.v3+json",
    }

    current_placement: Dict[str, int] = {}
    current_strategy: Optional[str] = None
    if bidding_fields_set:
        list_resp = await client.post(
            "/sp/campaigns/list",
            json={
                "campaignIdFilter": {"include": [campaign_id]},
                "maxResults": 1,
            },
            headers=headers,
        )
        if list_resp.status_code != 200:
            return {
                "success": False,
                "campaign_id": campaign_id,
                "error": f"HTTP {list_resp.status_code}: {list_resp.text[:300]}",
                "message": "Pre-fetch for placement merge failed",
            }
        campaigns = list_resp.json().get("campaigns", [])
        if not campaigns:
            return {
                "success": False,
                "campaign_id": campaign_id,
                "error": "Campaign not found",
                "message": "Pre-fetch for placement merge returned no campaign",
            }
        dynamic = campaigns[0].get("dynamicBidding") or {}
        current_strategy = dynamic.get("strategy")
        for entry in dynamic.get("placementBidding") or []:
            placement = entry.get("placement")
            pct = entry.get("percentage")
            if placement and pct is not None:
                current_placement[placement] = int(pct)

    campaign = {"campaignId": campaign_id}
    if name is not None:
        campaign["name"] = name
    if state is not None:
        campaign["state"] = state.upper()
    if budget_amount is not None or budget_type is not None:
        budget = {}
        if budget_amount is not None:
            budget["budget"] = budget_amount
        if budget_type is not None:
            budget["budgetType"] = budget_type.upper()
        else:
            budget["budgetType"] = "DAILY"
        campaign["budget"] = budget
    if start_date is not None:
        campaign["startDate"] = start_date
    if end_date is not None:
        campaign["endDate"] = end_date

    if bidding_fields_set:
        dynamic_payload: Dict[str, Any] = {}
        effective_strategy = (
            bidding_strategy if bidding_strategy is not None else current_strategy
        )
        if effective_strategy:
            dynamic_payload["strategy"] = effective_strategy.upper()

        merged_placement = dict(current_placement)
        if placement_top_pct is not None:
            merged_placement["PLACEMENT_TOP"] = int(placement_top_pct)
        if placement_product_page_pct is not None:
            merged_placement["PLACEMENT_PRODUCT_PAGE"] = int(placement_product_page_pct)
        if placement_rest_of_search_pct is not None:
            merged_placement["PLACEMENT_REST_OF_SEARCH"] = int(placement_rest_of_search_pct)

        if merged_placement:
            dynamic_payload["placementBidding"] = [
                {"placement": p, "percentage": v}
                for p, v in sorted(merged_placement.items())
            ]

        if dynamic_payload:
            campaign["dynamicBidding"] = dynamic_payload

    resp = await client.put(
        "/sp/campaigns",
        json={"campaigns": [campaign]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("campaigns", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "campaign_id": campaign_id,
                "message": f"Campaign {campaign_id} updated",
                "updated_fields": {k: v for k, v in campaign.items() if k != "campaignId"},
                "details": success_list[0],
            }
        elif error_list:
            err = error_list[0]
            return {
                "success": False,
                "campaign_id": campaign_id,
                "error": err.get("errors", err),
                "message": f"Failed to update campaign {campaign_id}",
            }
    return {
        "success": False,
        "campaign_id": campaign_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SP Campaign archive
# ---------------------------------------------------------------------------

async def archive_sp_campaign(campaign_id: str) -> dict:
    """Archive one Sponsored Products campaign.

    SP v3 splits state transitions (PUT /sp/campaigns — accepts only
    ENABLED/PAUSED) from archival (POST /sp/campaigns/delete). The 'delete'
    endpoint is misnamed: it archives. ARCHIVED is permanent and cannot be
    reversed through the API.

    :param campaign_id: Campaign ID to archive
    """
    from ..utils.http_client import get_authenticated_client

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spcampaign.v3+json",
        "Content-Type": "application/vnd.spcampaign.v3+json",
    }
    resp = await client.post(
        "/sp/campaigns/delete",
        json={"campaignIdFilter": {"include": [campaign_id]}},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("campaigns", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "campaign_id": campaign_id,
                "message": f"Campaign {campaign_id} archived",
                "updated_fields": {"state": "ARCHIVED"},
                "details": success_list[0],
            }
        elif error_list:
            err = error_list[0]
            return {
                "success": False,
                "campaign_id": campaign_id,
                "error": err.get("errors", err),
                "message": f"Failed to archive campaign {campaign_id}",
            }
    return {
        "success": False,
        "campaign_id": campaign_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SB Campaign updates
# ---------------------------------------------------------------------------

async def update_sb_campaigns(
    campaign_id: str,
    name: Optional[str] = None,
    state: Optional[str] = None,
    budget_amount: Optional[float] = None,
    budget_type: Optional[str] = None,
) -> dict:
    """Update one Sponsored Brands campaign.

    :param campaign_id: Campaign ID to update
    :param name: New campaign name
    :param state: New state (ENABLED, PAUSED, ARCHIVED)
    :param budget_amount: New budget amount
    :param budget_type: Budget type (DAILY)
    """
    from ..utils.http_client import get_authenticated_client

    campaign = {"campaignId": campaign_id}
    if name is not None:
        campaign["name"] = name
    if state is not None:
        campaign["state"] = state.upper()
    if budget_amount is not None or budget_type is not None:
        budget = {}
        if budget_amount is not None:
            budget["budget"] = budget_amount
        if budget_type is not None:
            budget["budgetType"] = budget_type.upper()
        else:
            budget["budgetType"] = "DAILY"
        campaign["budget"] = budget

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.sbcampaignresource.v4+json",
        "Content-Type": "application/vnd.sbcampaignresource.v4+json",
    }
    resp = await client.put(
        "/sb/v4/campaigns",
        json={"campaigns": [campaign]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("campaigns", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "campaign_id": campaign_id,
                "message": f"SB campaign {campaign_id} updated",
                "updated_fields": {k: v for k, v in campaign.items() if k != "campaignId"},
                "details": success_list[0],
            }
        elif error_list:
            err = error_list[0]
            return {
                "success": False,
                "campaign_id": campaign_id,
                "error": err.get("errors", err),
                "message": f"Failed to update SB campaign {campaign_id}",
            }
    return {
        "success": False,
        "campaign_id": campaign_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SP Ad Group updates
# ---------------------------------------------------------------------------

async def update_sp_ad_groups(
    ad_group_id: str,
    name: Optional[str] = None,
    state: Optional[str] = None,
    default_bid: Optional[float] = None,
) -> dict:
    """Update one Sponsored Products ad group.

    The SP v3 PUT /sp/adGroups endpoint only accepts state values ENABLED
    or PAUSED — to archive an ad group, use archive_sp_ad_group, which
    routes through POST /sp/adGroups/delete.

    :param ad_group_id: Ad group ID to update
    :param name: New ad group name
    :param state: New state (ENABLED, PAUSED)
    :param default_bid: New default bid amount
    """
    from ..utils.http_client import get_authenticated_client

    ad_group = {"adGroupId": ad_group_id}
    if name is not None:
        ad_group["name"] = name
    if state is not None:
        ad_group["state"] = state.upper()
    if default_bid is not None:
        ad_group["defaultBid"] = default_bid

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spAdGroup.v3+json",
        "Content-Type": "application/vnd.spAdGroup.v3+json",
    }
    resp = await client.put(
        "/sp/adGroups",
        json={"adGroups": [ad_group]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("adGroups", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "ad_group_id": ad_group_id,
                "message": f"Ad group {ad_group_id} updated",
                "updated_fields": {k: v for k, v in ad_group.items() if k != "adGroupId"},
                "details": success_list[0],
            }
        elif error_list:
            return {
                "success": False,
                "ad_group_id": ad_group_id,
                "error": error_list[0].get("errors", error_list[0]),
                "message": f"Failed to update ad group {ad_group_id}",
            }
    return {
        "success": False,
        "ad_group_id": ad_group_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


async def archive_sp_ad_group(ad_group_id: str) -> dict:
    """Archive one Sponsored Products ad group.

    SP v3 splits state transitions (PUT /sp/adGroups — accepts only
    ENABLED/PAUSED) from archival (POST /sp/adGroups/delete). The 'delete'
    endpoint is misnamed: it archives. ARCHIVED is permanent and cannot be
    reversed through the API.

    :param ad_group_id: Ad group ID to archive
    """
    from ..utils.http_client import get_authenticated_client

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spAdGroup.v3+json",
        "Content-Type": "application/vnd.spAdGroup.v3+json",
    }
    resp = await client.post(
        "/sp/adGroups/delete",
        json={"adGroupIdFilter": {"include": [ad_group_id]}},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("adGroups", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "ad_group_id": ad_group_id,
                "message": f"Ad group {ad_group_id} archived",
                "updated_fields": {"state": "ARCHIVED"},
                "details": success_list[0],
            }
        elif error_list:
            err = error_list[0]
            return {
                "success": False,
                "ad_group_id": ad_group_id,
                "error": err.get("errors", err),
                "message": f"Failed to archive ad group {ad_group_id}",
            }
    return {
        "success": False,
        "ad_group_id": ad_group_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SP Keyword updates
# ---------------------------------------------------------------------------

async def update_sp_keywords(
    keyword_id: str,
    state: Optional[str] = None,
    bid: Optional[float] = None,
) -> dict:
    """Update one Sponsored Products keyword.

    The SP v3 PUT /sp/keywords endpoint only accepts state values ENABLED
    or PAUSED — to archive a keyword, use archive_sp_keyword, which
    routes through POST /sp/keywords/delete.

    :param keyword_id: Keyword ID to update
    :param state: New state (ENABLED, PAUSED)
    :param bid: New bid amount
    """
    from ..utils.http_client import get_authenticated_client

    keyword = {"keywordId": keyword_id}
    if state is not None:
        keyword["state"] = state.upper()
    if bid is not None:
        keyword["bid"] = bid

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spKeyword.v3+json",
        "Content-Type": "application/vnd.spKeyword.v3+json",
    }
    resp = await client.put(
        "/sp/keywords",
        json={"keywords": [keyword]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("keywords", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "keyword_id": keyword_id,
                "message": f"Keyword {keyword_id} updated",
                "updated_fields": {k: v for k, v in keyword.items() if k != "keywordId"},
                "details": success_list[0],
            }
        elif error_list:
            return {
                "success": False,
                "keyword_id": keyword_id,
                "error": error_list[0].get("errors", error_list[0]),
                "message": f"Failed to update keyword {keyword_id}",
            }
    return {
        "success": False,
        "keyword_id": keyword_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


async def archive_sp_keyword(keyword_id: str) -> dict:
    """Archive one Sponsored Products keyword.

    SP v3 splits state transitions (PUT /sp/keywords — accepts only
    ENABLED/PAUSED) from archival (POST /sp/keywords/delete). The 'delete'
    endpoint is misnamed: it archives. ARCHIVED is permanent and cannot be
    reversed through the API.

    :param keyword_id: Keyword ID to archive
    """
    from ..utils.http_client import get_authenticated_client

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spKeyword.v3+json",
        "Content-Type": "application/vnd.spKeyword.v3+json",
    }
    resp = await client.post(
        "/sp/keywords/delete",
        json={"keywordIdFilter": {"include": [keyword_id]}},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("keywords", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "keyword_id": keyword_id,
                "message": f"Keyword {keyword_id} archived",
                "updated_fields": {"state": "ARCHIVED"},
                "details": success_list[0],
            }
        elif error_list:
            err = error_list[0]
            return {
                "success": False,
                "keyword_id": keyword_id,
                "error": err.get("errors", err),
                "message": f"Failed to archive keyword {keyword_id}",
            }
    return {
        "success": False,
        "keyword_id": keyword_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SP Product Ad updates
# ---------------------------------------------------------------------------

async def update_sp_product_ads(
    ad_id: str,
    state: Optional[str] = None,
) -> dict:
    """Update one Sponsored Products product ad (state only).

    The SP v3 PUT /sp/productAds endpoint only accepts state values
    ENABLED or PAUSED — to archive a product ad, use archive_sp_product_ad,
    which routes through POST /sp/productAds/delete.

    :param ad_id: Product ad ID to update
    :param state: New state (ENABLED, PAUSED)
    """
    from ..utils.http_client import get_authenticated_client

    ad = {"adId": ad_id}
    if state is not None:
        ad["state"] = state.upper()

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spProductAd.v3+json",
        "Content-Type": "application/vnd.spProductAd.v3+json",
    }
    resp = await client.put(
        "/sp/productAds",
        json={"productAds": [ad]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("productAds", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "ad_id": ad_id,
                "message": f"Product ad {ad_id} updated",
                "updated_fields": {k: v for k, v in ad.items() if k != "adId"},
                "details": success_list[0],
            }
        elif error_list:
            return {
                "success": False,
                "ad_id": ad_id,
                "error": error_list[0].get("errors", error_list[0]),
                "message": f"Failed to update product ad {ad_id}",
            }
    return {
        "success": False,
        "ad_id": ad_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


async def archive_sp_product_ad(ad_id: str) -> dict:
    """Archive one Sponsored Products product ad.

    SP v3 splits state transitions (PUT /sp/productAds — accepts only
    ENABLED/PAUSED) from archival (POST /sp/productAds/delete). The
    'delete' endpoint is misnamed: it archives. ARCHIVED is permanent and
    cannot be reversed through the API. The filter key is `adIdFilter`
    (not `productAdIdFilter`) because the ID field on a product ad is
    `adId`.

    :param ad_id: Product ad ID to archive
    """
    from ..utils.http_client import get_authenticated_client

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spProductAd.v3+json",
        "Content-Type": "application/vnd.spProductAd.v3+json",
    }
    resp = await client.post(
        "/sp/productAds/delete",
        json={"adIdFilter": {"include": [ad_id]}},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("productAds", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "ad_id": ad_id,
                "message": f"Product ad {ad_id} archived",
                "updated_fields": {"state": "ARCHIVED"},
                "details": success_list[0],
            }
        elif error_list:
            err = error_list[0]
            return {
                "success": False,
                "ad_id": ad_id,
                "error": err.get("errors", err),
                "message": f"Failed to archive product ad {ad_id}",
            }
    return {
        "success": False,
        "ad_id": ad_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SP Ad Group listing
# ---------------------------------------------------------------------------

async def list_sp_ad_groups(
    campaign_id: Optional[str] = None,
    state_filter: Optional[str] = None,
    max_results: int = 100,
    next_token: Optional[str] = None,
) -> dict:
    """List Sponsored Products ad groups with optional filters.

    :param campaign_id: Filter by campaign ID
    :param state_filter: Comma-separated states (ENABLED,PAUSED,ARCHIVED)
    :param max_results: Max results per page (default 100)
    :param next_token: Pagination token from previous response
    """
    from ..utils.http_client import get_authenticated_client

    body: dict = {"maxResults": max_results}
    if next_token:
        body["nextToken"] = next_token
    if state_filter:
        states = [s.strip().upper() for s in state_filter.split(",")]
        body["stateFilter"] = {"include": states}
    if campaign_id:
        body["campaignIdFilter"] = {"include": [campaign_id]}

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spAdGroup.v3+json",
        "Content-Type": "application/vnd.spAdGroup.v3+json",
    }
    resp = await client.post(
        "/sp/adGroups/list",
        json=body,
        headers=headers,
    )

    if resp.status_code == 200:
        data = resp.json()
        ad_groups = data.get("adGroups", [])
        items = []
        for ag in ad_groups:
            items.append({
                "ad_group_id": ag.get("adGroupId"),
                "name": ag.get("name"),
                "campaign_id": ag.get("campaignId"),
                "state": ag.get("state"),
                "default_bid": ag.get("defaultBid"),
            })
        return {
            "success": True,
            "items": items,
            "count": len(items),
            "next_token": data.get("nextToken"),
        }
    return {
        "success": False,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "items": [],
        "count": 0,
    }


# ---------------------------------------------------------------------------
# SP Keyword listing
# ---------------------------------------------------------------------------

async def list_sp_keywords(
    campaign_id: Optional[str] = None,
    ad_group_id: Optional[str] = None,
    state_filter: Optional[str] = None,
    max_results: int = 100,
    next_token: Optional[str] = None,
) -> dict:
    """List Sponsored Products keywords with optional filters.

    :param campaign_id: Filter by campaign ID
    :param ad_group_id: Filter by ad group ID
    :param state_filter: Comma-separated states (ENABLED,PAUSED,ARCHIVED)
    :param max_results: Max results per page (default 100)
    :param next_token: Pagination token from previous response
    """
    from ..utils.http_client import get_authenticated_client

    body: dict = {"maxResults": max_results}
    if next_token:
        body["nextToken"] = next_token
    if state_filter:
        states = [s.strip().upper() for s in state_filter.split(",")]
        body["stateFilter"] = {"include": states}
    if campaign_id:
        body["campaignIdFilter"] = {"include": [campaign_id]}
    if ad_group_id:
        body["adGroupIdFilter"] = {"include": [ad_group_id]}

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spKeyword.v3+json",
        "Content-Type": "application/vnd.spKeyword.v3+json",
    }
    resp = await client.post(
        "/sp/keywords/list",
        json=body,
        headers=headers,
    )

    if resp.status_code == 200:
        data = resp.json()
        keywords = data.get("keywords", [])
        items = []
        for kw in keywords:
            items.append({
                "keyword_id": kw.get("keywordId"),
                "keyword_text": kw.get("keywordText"),
                "match_type": kw.get("matchType"),
                "campaign_id": kw.get("campaignId"),
                "ad_group_id": kw.get("adGroupId"),
                "state": kw.get("state"),
                "bid": kw.get("bid"),
            })
        return {
            "success": True,
            "items": items,
            "count": len(items),
            "next_token": data.get("nextToken"),
        }
    return {
        "success": False,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "items": [],
        "count": 0,
    }


# ---------------------------------------------------------------------------
# SP Campaign creation
# ---------------------------------------------------------------------------

async def create_sp_campaign(
    name: str,
    targeting_type: str,
    budget_amount: float,
    state: str = "ENABLED",
    portfolio_id: Optional[str] = None,
    bidding_strategy: str = "LEGACY_FOR_SALES",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> dict:
    """Create a new Sponsored Products campaign.

    :param name: Campaign name
    :param targeting_type: MANUAL or AUTO
    :param budget_amount: Daily budget amount
    :param state: Initial state (ENABLED, PAUSED)
    :param portfolio_id: Portfolio ID to assign to
    :param bidding_strategy: Bidding strategy (LEGACY_FOR_SALES = down only,
        AUTO_FOR_SALES = up and down, MANUAL = fixed)
    :param start_date: Start date YYYYMMDD (defaults to today)
    :param end_date: End date YYYYMMDD
    """
    from datetime import datetime

    from ..utils.http_client import get_authenticated_client

    if start_date is None:
        start_date = datetime.now().strftime("%Y%m%d")

    campaign: dict = {
        "name": name,
        "targetingType": targeting_type.upper(),
        "state": state.upper(),
        "dynamicBidding": {"strategy": bidding_strategy},
        "budget": {"budgetType": "DAILY", "budget": budget_amount},
        "startDate": start_date,
    }
    if portfolio_id is not None:
        campaign["portfolioId"] = portfolio_id
    if end_date is not None:
        campaign["endDate"] = end_date

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spcampaign.v3+json",
        "Content-Type": "application/vnd.spcampaign.v3+json",
    }
    resp = await client.post(
        "/sp/campaigns",
        json={"campaigns": [campaign]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("campaigns", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            created = success_list[0]
            return {
                "success": True,
                "campaign_id": created.get("campaignId", created.get("campaign", {}).get("campaignId")),
                "message": f"Campaign '{name}' created",
                "details": created,
            }
        elif error_list:
            err = error_list[0]
            return {
                "success": False,
                "campaign_id": None,
                "error": err.get("errors", err),
                "message": f"Failed to create campaign '{name}'",
            }
    return {
        "success": False,
        "campaign_id": None,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SP Ad Group creation
# ---------------------------------------------------------------------------

async def create_sp_ad_group(
    campaign_id: str,
    name: str,
    default_bid: float,
    state: str = "ENABLED",
) -> dict:
    """Create a new Sponsored Products ad group.

    :param campaign_id: Parent campaign ID
    :param name: Ad group name
    :param default_bid: Default bid amount
    :param state: Initial state (ENABLED, PAUSED)
    """
    from ..utils.http_client import get_authenticated_client

    ad_group = {
        "campaignId": campaign_id,
        "name": name,
        "state": state.upper(),
        "defaultBid": default_bid,
    }

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spAdGroup.v3+json",
        "Content-Type": "application/vnd.spAdGroup.v3+json",
    }
    resp = await client.post(
        "/sp/adGroups",
        json={"adGroups": [ad_group]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("adGroups", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            created = success_list[0]
            return {
                "success": True,
                "ad_group_id": created.get("adGroupId", created.get("adGroup", {}).get("adGroupId")),
                "message": f"Ad group '{name}' created",
                "details": created,
            }
        elif error_list:
            return {
                "success": False,
                "ad_group_id": None,
                "error": error_list[0].get("errors", error_list[0]),
                "message": f"Failed to create ad group '{name}'",
            }
    return {
        "success": False,
        "ad_group_id": None,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SP Keyword creation
# ---------------------------------------------------------------------------

async def create_sp_keyword(
    campaign_id: str,
    ad_group_id: str,
    keyword_text: str,
    match_type: str,
    bid: float,
    state: str = "ENABLED",
) -> dict:
    """Create a new Sponsored Products keyword.

    :param campaign_id: Parent campaign ID
    :param ad_group_id: Parent ad group ID
    :param keyword_text: The keyword text
    :param match_type: EXACT, PHRASE, or BROAD
    :param bid: Bid amount
    :param state: Initial state (ENABLED, PAUSED)
    """
    from ..utils.http_client import get_authenticated_client

    keyword = {
        "campaignId": campaign_id,
        "adGroupId": ad_group_id,
        "keywordText": keyword_text,
        "matchType": match_type.upper(),
        "bid": bid,
        "state": state.upper(),
    }

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spKeyword.v3+json",
        "Content-Type": "application/vnd.spKeyword.v3+json",
    }
    resp = await client.post(
        "/sp/keywords",
        json={"keywords": [keyword]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("keywords", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            created = success_list[0]
            return {
                "success": True,
                "keyword_id": created.get("keywordId", created.get("keyword", {}).get("keywordId")),
                "message": f"Keyword '{keyword_text}' created",
                "details": created,
            }
        elif error_list:
            return {
                "success": False,
                "keyword_id": None,
                "error": error_list[0].get("errors", error_list[0]),
                "message": f"Failed to create keyword '{keyword_text}'",
            }
    return {
        "success": False,
        "keyword_id": None,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SP Product Ad creation
# ---------------------------------------------------------------------------

async def create_sp_product_ad(
    campaign_id: str,
    ad_group_id: str,
    asin: Optional[str] = None,
    sku: Optional[str] = None,
    state: str = "ENABLED",
) -> dict:
    """Create a new Sponsored Products product ad.

    Seller accounts must pass ``sku`` (Amazon requires merchantSku for
    seller ads). Vendor accounts must pass ``asin``. At least one must
    be provided.

    :param campaign_id: Parent campaign ID
    :param ad_group_id: Parent ad group ID
    :param asin: Product ASIN (vendor accounts)
    :param sku: Merchant SKU (seller accounts)
    :param state: Initial state (ENABLED, PAUSED)
    """
    from ..utils.http_client import get_authenticated_client

    if asin is None and sku is None:
        return {
            "success": False,
            "ad_id": None,
            "error": "Must provide either asin (vendor) or sku (seller)",
            "message": "Missing product identifier",
        }

    product_ad: Dict[str, Any] = {
        "campaignId": campaign_id,
        "adGroupId": ad_group_id,
        "state": state.upper(),
    }
    if asin is not None:
        product_ad["asin"] = asin
    if sku is not None:
        product_ad["sku"] = sku

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spProductAd.v3+json",
        "Content-Type": "application/vnd.spProductAd.v3+json",
    }
    resp = await client.post(
        "/sp/productAds",
        json={"productAds": [product_ad]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("productAds", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            created = success_list[0]
            ident = sku or asin
            return {
                "success": True,
                "ad_id": created.get("adId", created.get("productAd", {}).get("adId")),
                "message": f"Product ad for {ident} created",
                "details": created,
            }
        elif error_list:
            ident = sku or asin
            return {
                "success": False,
                "ad_id": None,
                "error": error_list[0].get("errors", error_list[0]),
                "message": f"Failed to create product ad for {ident}",
            }
    return {
        "success": False,
        "ad_id": None,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SP Campaign listing
# ---------------------------------------------------------------------------

async def list_sp_campaigns(
    name_filter: Optional[str] = None,
    state_filter: Optional[str] = None,
    portfolio_id_filter: Optional[str] = None,
    max_results: int = 100,
    next_token: Optional[str] = None,
    include_extended_data: bool = False,
) -> dict:
    """List Sponsored Products campaigns with optional filters.

    :param name_filter: Filter by campaign name (contains match)
    :param state_filter: Comma-separated states (ENABLED,PAUSED,ARCHIVED)
    :param portfolio_id_filter: Filter by portfolio ID
    :param max_results: Max results per page (default 100)
    :param next_token: Pagination token from previous response
    :param include_extended_data: Request extendedData fields. Surfaces
        servingStatus (delivery health — CAMPAIGN_OUT_OF_BUDGET, etc.),
        servingStatusDetails (human-readable reasons), creationDateTime,
        and lastUpdateDateTime on each item. Slightly slower upstream; off
        by default.
    """
    from ..utils.http_client import get_authenticated_client

    body: dict = {"maxResults": max_results}
    if next_token:
        body["nextToken"] = next_token
    if state_filter:
        states = [s.strip().upper() for s in state_filter.split(",")]
        body["stateFilter"] = {"include": states}
    if name_filter:
        body["nameFilter"] = {"queryTermMatchType": "BROAD_MATCH", "include": [name_filter]}
    if portfolio_id_filter:
        body["portfolioIdFilter"] = {"include": [portfolio_id_filter]}
    if include_extended_data:
        body["includeExtendedDataFields"] = True

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spcampaign.v3+json",
        "Content-Type": "application/vnd.spcampaign.v3+json",
    }
    resp = await client.post(
        "/sp/campaigns/list",
        json=body,
        headers=headers,
    )

    if resp.status_code == 200:
        data = resp.json()
        campaigns = data.get("campaigns", [])
        items = []
        for c in campaigns:
            budget = c.get("budget", {})
            dynamic = c.get("dynamicBidding", {}) or {}
            placement_map = {
                p.get("placement"): p.get("percentage")
                for p in (dynamic.get("placementBidding") or [])
            }
            extended_raw = c.get("extendedData")
            extended = extended_raw or {}
            items.append({
                "campaign_id": c.get("campaignId"),
                "name": c.get("name"),
                "state": c.get("state"),
                "targeting_type": c.get("targetingType"),
                "budget_amount": budget.get("budget"),
                "budget_type": budget.get("budgetType"),
                "portfolio_id": c.get("portfolioId"),
                "start_date": c.get("startDate"),
                "bidding_strategy": dynamic.get("strategy"),
                "placement_top_pct": placement_map.get("PLACEMENT_TOP", 0),
                "placement_product_page_pct": placement_map.get("PLACEMENT_PRODUCT_PAGE", 0),
                "placement_rest_of_search_pct": placement_map.get("PLACEMENT_REST_OF_SEARCH", 0),
                "serving_status": extended.get("servingStatus"),
                "serving_status_details": extended.get("servingStatusDetails"),
                "creation_date_time": extended.get("creationDateTime"),
                "last_update_date_time": extended.get("lastUpdateDateTime"),
                # Lossless passthrough: any extendedData field the API
                # returns lives here, even ones not yet flattened above.
                "extended_data": extended_raw,
            })
        return {
            "success": True,
            "items": items,
            "count": len(items),
            "next_token": data.get("nextToken"),
        }
    return {
        "success": False,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "items": [],
        "count": 0,
    }


# ---------------------------------------------------------------------------
# SP Product Ad listing
# ---------------------------------------------------------------------------

async def list_sp_product_ads(
    campaign_id: Optional[str] = None,
    ad_group_id: Optional[str] = None,
    state_filter: Optional[str] = None,
    max_results: int = 100,
    next_token: Optional[str] = None,
) -> dict:
    """List Sponsored Products product ads with optional filters.

    :param campaign_id: Filter by campaign ID
    :param ad_group_id: Filter by ad group ID
    :param state_filter: Comma-separated states (ENABLED,PAUSED,ARCHIVED)
    :param max_results: Max results per page (default 100)
    :param next_token: Pagination token from previous response
    """
    from ..utils.http_client import get_authenticated_client

    body: dict = {"maxResults": max_results}
    if next_token:
        body["nextToken"] = next_token
    if state_filter:
        states = [s.strip().upper() for s in state_filter.split(",")]
        body["stateFilter"] = {"include": states}
    if campaign_id:
        body["campaignIdFilter"] = {"include": [campaign_id]}
    if ad_group_id:
        body["adGroupIdFilter"] = {"include": [ad_group_id]}

    client = await get_authenticated_client()
    headers = {
        "Accept": "application/vnd.spProductAd.v3+json",
        "Content-Type": "application/vnd.spProductAd.v3+json",
    }
    resp = await client.post(
        "/sp/productAds/list",
        json=body,
        headers=headers,
    )

    if resp.status_code == 200:
        data = resp.json()
        ads = data.get("productAds", [])
        items = []
        for ad in ads:
            items.append({
                "ad_id": ad.get("adId"),
                "campaign_id": ad.get("campaignId"),
                "ad_group_id": ad.get("adGroupId"),
                "asin": ad.get("asin"),
                "state": ad.get("state"),
            })
        return {
            "success": True,
            "items": items,
            "count": len(items),
            "next_token": data.get("nextToken"),
        }
    return {
        "success": False,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "items": [],
        "count": 0,
    }


# ---------------------------------------------------------------------------
# SP Portfolio listing (for resolving portfolio names -> IDs)
# ---------------------------------------------------------------------------

_PORTFOLIO_CT = "application/vnd.spportfolio.v1+json"


async def list_sp_portfolios(
    name_filter: Optional[str] = None,
    portfolio_id_filter: Optional[str] = None,
    max_results: int = 100,
    next_token: Optional[str] = None,
) -> dict:
    """List Sponsored Products portfolios for the active profile.

    :param name_filter: Filter by portfolio name (BROAD match)
    :param portfolio_id_filter: Filter by specific portfolio ID
    :param max_results: Max results per page (default 100)
    :param next_token: Pagination token
    """
    from ..utils.http_client import get_authenticated_client

    body: dict = {"maxResults": max_results}
    if next_token:
        body["nextToken"] = next_token
    if name_filter:
        body["nameFilter"] = {
            "queryTermMatchType": "BROAD_MATCH",
            "include": [name_filter],
        }
    if portfolio_id_filter:
        body["portfolioIdFilter"] = {"include": [portfolio_id_filter]}

    client = await get_authenticated_client()
    headers = {"Accept": _PORTFOLIO_CT, "Content-Type": _PORTFOLIO_CT}
    resp = await client.post(
        "/portfolios/list",
        json=body,
        headers=headers,
    )

    if resp.status_code == 200:
        data = resp.json()
        portfolios = data.get("portfolios", [])
        items = []
        for p in portfolios:
            items.append({
                "portfolio_id": p.get("portfolioId"),
                "name": p.get("name"),
                "state": p.get("state"),
                "in_budget": p.get("inBudget"),
                "budget_policy": p.get("budget", {}).get("policy"),
                "budget_currency": p.get("budget", {}).get("currencyCode"),
            })
        return {
            "success": True,
            "items": items,
            "count": len(items),
            "total_results": data.get("totalResults"),
            "next_token": data.get("nextToken"),
        }
    return {
        "success": False,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "items": [],
        "count": 0,
    }


# ---------------------------------------------------------------------------
# SP Campaign Negative Keywords (create / list / update)
# ---------------------------------------------------------------------------

_NEG_KW_CT = "application/vnd.spCampaignNegativeKeyword.v3+json"


async def create_sp_negative_keyword(
    campaign_id: str,
    keyword_text: str,
    match_type: str,
    state: str = "ENABLED",
) -> dict:
    """Create a campaign-level negative keyword for Sponsored Products.

    :param campaign_id: Parent campaign ID
    :param keyword_text: The keyword text to negate
    :param match_type: NEGATIVE_EXACT or NEGATIVE_PHRASE
    :param state: Initial state (ENABLED, PAUSED)
    """
    from ..utils.http_client import get_authenticated_client

    neg_kw = {
        "campaignId": campaign_id,
        "keywordText": keyword_text,
        "matchType": match_type.upper(),
        "state": state.upper(),
    }
    client = await get_authenticated_client()
    headers = {"Accept": _NEG_KW_CT, "Content-Type": _NEG_KW_CT}
    resp = await client.post(
        "/sp/campaignNegativeKeywords",
        json={"campaignNegativeKeywords": [neg_kw]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("campaignNegativeKeywords", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            created = success_list[0]
            kwid = created.get("keywordId") or created.get(
                "campaignNegativeKeyword", {}
            ).get("keywordId")
            return {
                "success": True,
                "keyword_id": kwid,
                "message": f"Negative keyword '{keyword_text}' created",
                "details": created,
            }
        elif error_list:
            return {
                "success": False,
                "keyword_id": None,
                "error": error_list[0].get("errors", error_list[0]),
                "message": f"Failed to create negative keyword '{keyword_text}'",
            }
    return {
        "success": False,
        "keyword_id": None,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


async def list_sp_negative_keywords(
    campaign_id: Optional[str] = None,
    state_filter: Optional[str] = None,
    max_results: int = 100,
    next_token: Optional[str] = None,
) -> dict:
    """List campaign-level negative keywords with optional filters.

    :param campaign_id: Filter by campaign ID
    :param state_filter: Comma-separated states (ENABLED,PAUSED,ARCHIVED)
    :param max_results: Max results per page (default 100)
    :param next_token: Pagination token from previous response
    """
    from ..utils.http_client import get_authenticated_client

    body: dict = {"maxResults": max_results}
    if next_token:
        body["nextToken"] = next_token
    if state_filter:
        states = [s.strip().upper() for s in state_filter.split(",")]
        body["stateFilter"] = {"include": states}
    if campaign_id:
        body["campaignIdFilter"] = {"include": [campaign_id]}

    client = await get_authenticated_client()
    headers = {"Accept": _NEG_KW_CT, "Content-Type": _NEG_KW_CT}
    resp = await client.post(
        "/sp/campaignNegativeKeywords/list",
        json=body,
        headers=headers,
    )

    if resp.status_code == 200:
        data = resp.json()
        items_raw = data.get("campaignNegativeKeywords", [])
        items = []
        for kw in items_raw:
            items.append({
                "keyword_id": kw.get("keywordId"),
                "keyword_text": kw.get("keywordText"),
                "match_type": kw.get("matchType"),
                "campaign_id": kw.get("campaignId"),
                "state": kw.get("state"),
            })
        return {
            "success": True,
            "items": items,
            "count": len(items),
            "next_token": data.get("nextToken"),
        }
    return {
        "success": False,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "items": [],
        "count": 0,
    }


async def update_sp_negative_keywords(
    keyword_id: str,
    state: Optional[str] = None,
) -> dict:
    """Update a campaign-level negative keyword (state only).

    :param keyword_id: Negative keyword ID
    :param state: New state (ENABLED, PAUSED, ARCHIVED)
    """
    from ..utils.http_client import get_authenticated_client

    neg_kw = {"keywordId": keyword_id}
    if state is not None:
        neg_kw["state"] = state.upper()

    client = await get_authenticated_client()
    headers = {"Accept": _NEG_KW_CT, "Content-Type": _NEG_KW_CT}
    resp = await client.put(
        "/sp/campaignNegativeKeywords",
        json={"campaignNegativeKeywords": [neg_kw]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("campaignNegativeKeywords", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "keyword_id": keyword_id,
                "message": f"Negative keyword {keyword_id} updated",
                "updated_fields": {k: v for k, v in neg_kw.items() if k != "keywordId"},
                "details": success_list[0],
            }
        elif error_list:
            return {
                "success": False,
                "keyword_id": keyword_id,
                "error": error_list[0].get("errors", error_list[0]),
                "message": f"Failed to update negative keyword {keyword_id}",
            }
    return {
        "success": False,
        "keyword_id": keyword_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SP Ad Group Negative Keywords (create / list / update)
# ---------------------------------------------------------------------------
# SP v3 distinguishes campaign-scope and ad-group-scope negative keywords by
# endpoint family. Ad-group scope uses /sp/negativeKeywords with
# application/vnd.spNegativeKeyword.v3+json. Campaign scope (above) uses
# /sp/campaignNegativeKeywords with vnd.spCampaignNegativeKeyword.v3+json.

_AG_NEG_KW_CT = "application/vnd.spNegativeKeyword.v3+json"


async def create_sp_ad_group_negative_keyword(
    campaign_id: str,
    ad_group_id: str,
    keyword_text: str,
    match_type: str,
    state: str = "ENABLED",
) -> dict:
    """Create an ad-group-level negative keyword for Sponsored Products.

    :param campaign_id: Parent campaign ID
    :param ad_group_id: Parent ad group ID
    :param keyword_text: The keyword text to negate
    :param match_type: NEGATIVE_EXACT or NEGATIVE_PHRASE
    :param state: Initial state (ENABLED, PAUSED)
    """
    from ..utils.http_client import get_authenticated_client

    neg_kw = {
        "campaignId": campaign_id,
        "adGroupId": ad_group_id,
        "keywordText": keyword_text,
        "matchType": match_type.upper(),
        "state": state.upper(),
    }
    client = await get_authenticated_client()
    headers = {"Accept": _AG_NEG_KW_CT, "Content-Type": _AG_NEG_KW_CT}
    resp = await client.post(
        "/sp/negativeKeywords",
        json={"negativeKeywords": [neg_kw]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("negativeKeywords", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            created = success_list[0]
            kwid = created.get("keywordId") or created.get(
                "negativeKeyword", {}
            ).get("keywordId")
            return {
                "success": True,
                "keyword_id": kwid,
                "message": f"Ad-group negative keyword '{keyword_text}' created",
                "details": created,
            }
        elif error_list:
            return {
                "success": False,
                "keyword_id": None,
                "error": error_list[0].get("errors", error_list[0]),
                "message": f"Failed to create ad-group negative keyword '{keyword_text}'",
            }
    return {
        "success": False,
        "keyword_id": None,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


async def list_sp_ad_group_negative_keywords(
    campaign_id: Optional[str] = None,
    ad_group_id: Optional[str] = None,
    state_filter: Optional[str] = None,
    max_results: int = 100,
    next_token: Optional[str] = None,
) -> dict:
    """List ad-group-level negative keywords with optional filters.

    :param campaign_id: Filter by campaign ID
    :param ad_group_id: Filter by ad group ID
    :param state_filter: Comma-separated states (ENABLED,PAUSED,ARCHIVED)
    :param max_results: Max results per page (default 100)
    :param next_token: Pagination token from previous response
    """
    from ..utils.http_client import get_authenticated_client

    body: dict = {"maxResults": max_results}
    if next_token:
        body["nextToken"] = next_token
    if state_filter:
        states = [s.strip().upper() for s in state_filter.split(",")]
        body["stateFilter"] = {"include": states}
    if campaign_id:
        body["campaignIdFilter"] = {"include": [campaign_id]}
    if ad_group_id:
        body["adGroupIdFilter"] = {"include": [ad_group_id]}

    client = await get_authenticated_client()
    headers = {"Accept": _AG_NEG_KW_CT, "Content-Type": _AG_NEG_KW_CT}
    resp = await client.post(
        "/sp/negativeKeywords/list",
        json=body,
        headers=headers,
    )

    if resp.status_code == 200:
        data = resp.json()
        items_raw = data.get("negativeKeywords", [])
        items = []
        for kw in items_raw:
            items.append({
                "keyword_id": kw.get("keywordId"),
                "keyword_text": kw.get("keywordText"),
                "match_type": kw.get("matchType"),
                "campaign_id": kw.get("campaignId"),
                "ad_group_id": kw.get("adGroupId"),
                "state": kw.get("state"),
            })
        return {
            "success": True,
            "items": items,
            "count": len(items),
            "next_token": data.get("nextToken"),
        }
    return {
        "success": False,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "items": [],
        "count": 0,
    }


async def update_sp_ad_group_negative_keywords(
    keyword_id: str,
    state: Optional[str] = None,
) -> dict:
    """Update an ad-group-level negative keyword (state only).

    :param keyword_id: Negative keyword ID
    :param state: New state (ENABLED, PAUSED, ARCHIVED)
    """
    from ..utils.http_client import get_authenticated_client

    neg_kw: dict = {"keywordId": keyword_id}
    if state is not None:
        neg_kw["state"] = state.upper()

    client = await get_authenticated_client()
    headers = {"Accept": _AG_NEG_KW_CT, "Content-Type": _AG_NEG_KW_CT}
    resp = await client.put(
        "/sp/negativeKeywords",
        json={"negativeKeywords": [neg_kw]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("negativeKeywords", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "keyword_id": keyword_id,
                "message": f"Ad-group negative keyword {keyword_id} updated",
                "updated_fields": {k: v for k, v in neg_kw.items() if k != "keywordId"},
                "details": success_list[0],
            }
        elif error_list:
            return {
                "success": False,
                "keyword_id": keyword_id,
                "error": error_list[0].get("errors", error_list[0]),
                "message": f"Failed to update ad-group negative keyword {keyword_id}",
            }
    return {
        "success": False,
        "keyword_id": keyword_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SP Targets (product targeting — create / list / update)
# ---------------------------------------------------------------------------

_TARGET_CT = "application/vnd.spTargetingClause.v3+json"


async def create_sp_target(
    campaign_id: str,
    ad_group_id: str,
    bid: float,
    target_asin: Optional[str] = None,
    expression: Optional[List[Dict[str, str]]] = None,
    expression_type: str = "MANUAL",
    state: str = "ENABLED",
) -> dict:
    """Create a product target in a manual SP campaign.

    Provide either `target_asin` (shortcut for ASIN-same-as targeting) OR
    `expression` (full predicate list, e.g. category targets).

    :param campaign_id: Parent campaign ID
    :param ad_group_id: Parent ad group ID
    :param bid: Bid amount
    :param target_asin: Shortcut — target a specific ASIN (ASIN_SAME_AS)
    :param expression: Full expression predicate list
        (e.g. [{"type": "ASIN_SAME_AS", "value": "B0..."}])
    :param expression_type: MANUAL (default) or AUTO
    :param state: Initial state (ENABLED, PAUSED)
    """
    from ..utils.http_client import get_authenticated_client

    if expression is None and target_asin is None:
        return {
            "success": False,
            "target_id": None,
            "error": "Must provide either target_asin or expression",
            "message": "Missing targeting expression",
        }
    if expression is None:
        expression = _asin_expression(target_asin)

    clause: Dict[str, Any] = {
        "campaignId": campaign_id,
        "adGroupId": ad_group_id,
        "expression": expression,
        "expressionType": expression_type.upper(),
        "bid": bid,
        "state": state.upper(),
    }

    client = await get_authenticated_client()
    headers = {"Accept": _TARGET_CT, "Content-Type": _TARGET_CT}
    resp = await client.post(
        "/sp/targets",
        json={"targetingClauses": [clause]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("targetingClauses", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            created = success_list[0]
            tid = created.get("targetId") or created.get(
                "targetingClause", {}
            ).get("targetId")
            return {
                "success": True,
                "target_id": tid,
                "message": "Target created",
                "details": created,
            }
        elif error_list:
            return {
                "success": False,
                "target_id": None,
                "error": error_list[0].get("errors", error_list[0]),
                "message": "Failed to create target",
            }
    return {
        "success": False,
        "target_id": None,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


async def list_sp_targets(
    campaign_id: Optional[str] = None,
    ad_group_id: Optional[str] = None,
    state_filter: Optional[str] = None,
    max_results: int = 100,
    next_token: Optional[str] = None,
) -> dict:
    """List Sponsored Products targeting clauses (targets).

    Returns both manual PT targets and auto-campaign targeting expressions
    (close-match, loose-match, substitutes, complements).

    :param campaign_id: Filter by campaign ID
    :param ad_group_id: Filter by ad group ID
    :param state_filter: Comma-separated states (ENABLED,PAUSED,ARCHIVED)
    :param max_results: Max results per page (default 100)
    :param next_token: Pagination token from previous response
    """
    from ..utils.http_client import get_authenticated_client

    body: dict = {"maxResults": max_results}
    if next_token:
        body["nextToken"] = next_token
    if state_filter:
        states = [s.strip().upper() for s in state_filter.split(",")]
        body["stateFilter"] = {"include": states}
    if campaign_id:
        body["campaignIdFilter"] = {"include": [campaign_id]}
    if ad_group_id:
        body["adGroupIdFilter"] = {"include": [ad_group_id]}

    client = await get_authenticated_client()
    headers = {"Accept": _TARGET_CT, "Content-Type": _TARGET_CT}
    resp = await client.post(
        "/sp/targets/list",
        json=body,
        headers=headers,
    )

    if resp.status_code == 200:
        data = resp.json()
        clauses = data.get("targetingClauses", [])
        items = []
        for c in clauses:
            items.append({
                "target_id": c.get("targetId"),
                "campaign_id": c.get("campaignId"),
                "ad_group_id": c.get("adGroupId"),
                "expression": c.get("expression"),
                "resolved_expression": c.get("resolvedExpression"),
                "expression_type": c.get("expressionType"),
                "state": c.get("state"),
                "bid": c.get("bid"),
            })
        return {
            "success": True,
            "items": items,
            "count": len(items),
            "next_token": data.get("nextToken"),
        }
    return {
        "success": False,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "items": [],
        "count": 0,
    }


async def update_sp_targets(
    target_id: str,
    bid: Optional[float] = None,
    state: Optional[str] = None,
) -> dict:
    """Update a Sponsored Products target (change bid or state).

    Also updates auto-campaign targeting expressions (close-match, loose-match,
    substitutes, complements) since those share the same /sp/targets endpoint.

    :param target_id: Target ID (also called targetingClause ID)
    :param bid: New bid amount
    :param state: New state (ENABLED, PAUSED, ARCHIVED)
    """
    from ..utils.http_client import get_authenticated_client

    clause: Dict[str, Any] = {"targetId": target_id}
    if bid is not None:
        clause["bid"] = bid
    if state is not None:
        clause["state"] = state.upper()

    client = await get_authenticated_client()
    headers = {"Accept": _TARGET_CT, "Content-Type": _TARGET_CT}
    resp = await client.put(
        "/sp/targets",
        json={"targetingClauses": [clause]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("targetingClauses", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "target_id": target_id,
                "message": f"Target {target_id} updated",
                "updated_fields": {k: v for k, v in clause.items() if k != "targetId"},
                "details": success_list[0],
            }
        elif error_list:
            return {
                "success": False,
                "target_id": target_id,
                "error": error_list[0].get("errors", error_list[0]),
                "message": f"Failed to update target {target_id}",
            }
    return {
        "success": False,
        "target_id": target_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


# ---------------------------------------------------------------------------
# SP Campaign Negative Targets (create / list / update)
# ---------------------------------------------------------------------------

_NEG_TGT_CT = "application/vnd.spCampaignNegativeTargetingClause.v3+json"


async def create_sp_negative_target(
    campaign_id: str,
    negative_asin: Optional[str] = None,
    expression: Optional[List[Dict[str, str]]] = None,
    state: str = "ENABLED",
) -> dict:
    """Create a campaign-level negative product target.

    Available only for AUTO campaigns (per Amazon Ads API). Provide either
    `negative_asin` or `expression`.

    :param campaign_id: Parent campaign ID (must be AUTO)
    :param negative_asin: Shortcut — block a specific ASIN (ASIN_SAME_AS)
    :param expression: Full expression predicate list
    :param state: Initial state (ENABLED, PAUSED)
    """
    from ..utils.http_client import get_authenticated_client

    if expression is None and negative_asin is None:
        return {
            "success": False,
            "target_id": None,
            "error": "Must provide either negative_asin or expression",
            "message": "Missing negative targeting expression",
        }
    if expression is None:
        expression = _asin_expression(negative_asin)

    clause: Dict[str, Any] = {
        "campaignId": campaign_id,
        "expression": expression,
        "state": state.upper(),
    }

    client = await get_authenticated_client()
    headers = {"Accept": _NEG_TGT_CT, "Content-Type": _NEG_TGT_CT}
    resp = await client.post(
        "/sp/campaignNegativeTargets",
        json={"campaignNegativeTargetingClauses": [clause]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("campaignNegativeTargetingClauses", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            created = success_list[0]
            tid = created.get("targetId") or created.get(
                "campaignNegativeTargetingClause", {}
            ).get("targetId")
            return {
                "success": True,
                "target_id": tid,
                "message": "Negative target created",
                "details": created,
            }
        elif error_list:
            return {
                "success": False,
                "target_id": None,
                "error": error_list[0].get("errors", error_list[0]),
                "message": "Failed to create negative target",
            }
    return {
        "success": False,
        "target_id": None,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }


async def list_sp_negative_targets(
    campaign_id: Optional[str] = None,
    state_filter: Optional[str] = None,
    max_results: int = 100,
    next_token: Optional[str] = None,
) -> dict:
    """List campaign-level negative targets.

    :param campaign_id: Filter by campaign ID
    :param state_filter: Comma-separated states (ENABLED,PAUSED,ARCHIVED)
    :param max_results: Max results per page (default 100)
    :param next_token: Pagination token from previous response
    """
    from ..utils.http_client import get_authenticated_client

    body: dict = {"maxResults": max_results}
    if next_token:
        body["nextToken"] = next_token
    if state_filter:
        states = [s.strip().upper() for s in state_filter.split(",")]
        body["stateFilter"] = {"include": states}
    if campaign_id:
        body["campaignIdFilter"] = {"include": [campaign_id]}

    client = await get_authenticated_client()
    headers = {"Accept": _NEG_TGT_CT, "Content-Type": _NEG_TGT_CT}
    resp = await client.post(
        "/sp/campaignNegativeTargets/list",
        json=body,
        headers=headers,
    )

    if resp.status_code == 200:
        data = resp.json()
        clauses = data.get("campaignNegativeTargetingClauses", [])
        items = []
        for c in clauses:
            items.append({
                "target_id": c.get("targetId"),
                "campaign_id": c.get("campaignId"),
                "expression": c.get("expression"),
                "resolved_expression": c.get("resolvedExpression"),
                "state": c.get("state"),
            })
        return {
            "success": True,
            "items": items,
            "count": len(items),
            "next_token": data.get("nextToken"),
        }
    return {
        "success": False,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "items": [],
        "count": 0,
    }


async def update_sp_negative_targets(
    target_id: str,
    state: Optional[str] = None,
) -> dict:
    """Update a campaign-level negative target (state only).

    :param target_id: Negative target ID
    :param state: New state (ENABLED, PAUSED, ARCHIVED)
    """
    from ..utils.http_client import get_authenticated_client

    clause: Dict[str, Any] = {"targetId": target_id}
    if state is not None:
        clause["state"] = state.upper()

    client = await get_authenticated_client()
    headers = {"Accept": _NEG_TGT_CT, "Content-Type": _NEG_TGT_CT}
    resp = await client.put(
        "/sp/campaignNegativeTargets",
        json={"campaignNegativeTargetingClauses": [clause]},
        headers=headers,
    )

    if resp.status_code in (200, 207):
        data = resp.json()
        results = data.get("campaignNegativeTargetingClauses", {})
        success_list = results.get("success", [])
        error_list = results.get("error", [])
        if success_list:
            return {
                "success": True,
                "target_id": target_id,
                "message": f"Negative target {target_id} updated",
                "updated_fields": {k: v for k, v in clause.items() if k != "targetId"},
                "details": success_list[0],
            }
        elif error_list:
            return {
                "success": False,
                "target_id": target_id,
                "error": error_list[0].get("errors", error_list[0]),
                "message": f"Failed to update negative target {target_id}",
            }
    return {
        "success": False,
        "target_id": target_id,
        "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
        "message": "API request failed",
    }
