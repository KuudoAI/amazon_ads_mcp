#!/usr/bin/env python3
"""Update prefixes in amazon_ads_openapi.json to follow 6-character convention."""

import json
from pathlib import Path

# Mapping of namespaces to new 6-char (or less) prefixes
PREFIX_MAP = {
    "AccountsProfiles": "acprof",
    "AccountsManagerAccounts": "acmgr",
    "AccountsAdsAccounts": "acads",
    "AccountsPortfolios": "acport",
    "AccountsBilling": "acbill",
    "AccountsAccountBudgets": "acbudg",
    "CampaignManage": "cm",
    "SponsoredProducts": "sp",
    "SponsoredBrandsV3": "sb3",
    "SponsoredBrandsV4": "sb4",
    "SponsoredDisplay": "sd",
    "SPSnapshotsSuggestedKeywords": "spsugg",  # for suggested keywords
    "AmazonDSPMeasurement": "dspmea",
    "AmazonDSPAdvertisers": "dspadv",
    "AmazonDSPAudiences": "dspaud",
    "AmazonDSPConversions": "dspcon",
    "AmazonDSPTargetKPIRecommendations": "dspkpi",
    "ReportingAsynchronousReportingVersion3": "rpasyn",
    "ReportingStoresAnalytics": "rpstr",
    "ReportingMarketingMixModeling": "rpmmm",
    "RecommendationsInsightsAudienceInsights": "riaud",
    "RecommendationsInsightsPartnerOpportunities": "ripart",
    "RecommendationsInsightsTacticalRecommendations": "ritact",
    "RecommendationsInsightsPersonaBuilder": "ripers",
    "AMCAdmin": "amc",
    "AMCWorkflow": "amcwf",
    "AMCRuleAudience": "amcrul",
    "AMCAdAudience": "amcad",
    "AudiencesDiscovery": "aud",
    "BrandMetricsBrandMetrics": "brand",
    "AmazonAttribution": "attr",
    "CreativesAssets": "creat",
    "ChangeHistory": "hist",
    "DataProvider": "data",
    "ProductsMetadata": "prodm",
    "ProductsEligibility": "prode",
    "ModerationResults": "mod",
    "UnifiedPreModerationResults": "premod",
    "AmazonMarketingStreamSubscriptions": "ams",
    "Locations": "loc",
    "ExportsSnapshots": "export",
    "MediaPlanningReachForecasting": "reach",
}

def main():
    config_path = Path(__file__).parent.parent / "config" / "amazon_ads_openapi.json"
    
    # Load config
    with open(config_path) as f:
        config = json.load(f)
    
    # Track changes
    changes = []
    unchanged = []
    
    # Update prefixes
    for item in config.get("openapiDownloads", []):
        namespace = item.get("namespace")
        old_prefix = item.get("prefix", "")
        
        if namespace in PREFIX_MAP:
            new_prefix = PREFIX_MAP[namespace]
            if old_prefix != new_prefix:
                changes.append(f"  {namespace}: '{old_prefix}' -> '{new_prefix}'")
                item["prefix"] = new_prefix
        else:
            unchanged.append(f"  {namespace}: '{old_prefix}' (no mapping)")
    
    # Save updated config
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    # Report changes
    print("Prefix Update Summary")
    print("=" * 50)
    
    if changes:
        print(f"\nUpdated {len(changes)} prefixes:")
        for change in sorted(changes):
            print(change)
    
    if unchanged:
        print(f"\nUnchanged {len(unchanged)} prefixes (no mapping defined):")
        for item in sorted(unchanged):
            print(item)
    
    print(f"\n✅ Config updated: {config_path}")
    print("\nNext steps:")
    print("1. Run: python .build/scripts/process_openapi_specs.py")
    print("2. Verify: All tool names are under 64 characters")

if __name__ == "__main__":
    main()