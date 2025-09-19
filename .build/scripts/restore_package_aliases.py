#!/usr/bin/env python3
"""Restore human-readable package aliases while keeping short prefixes for tool names."""

import json
from pathlib import Path

# Mapping of namespaces to their human-readable aliases
# These are what users will use in ADS_API_PACKAGES
PACKAGE_ALIASES = {
    "AccountsProfiles": "profiles",
    "AccountsManagerAccounts": "manager-accounts", 
    "AccountsAdsAccounts": "ads-accounts",
    "AccountsPortfolios": "portfolios",
    "AccountsBilling": "billing",
    "AccountsAccountBudgets": "budgets",
    "CampaignManage": "campaign-manage",
    "SponsoredProducts": "sp",
    "SponsoredBrandsV3": "sb-v3",
    "SponsoredBrandsV4": "sb-v4",
    "SponsoredDisplay": "sd",
    "SPSnapshotsSuggestedKeywords": "sp-suggested-keywords",
    "AmazonDSPMeasurement": "dsp-mea",
    "AmazonDSPAdvertisers": "dsp-adv",
    "AmazonDSPAudiences": "dsp-aud",
    "AmazonDSPConversions": "dsp-con",
    "AmazonDSPTargetKPIRecommendations": "dsp-kpi",
    "ReportingVersion3": "async-reports-v3",
    "StoresAnalytics": "store-analytics",
    "ReportingMarketingMixModeling": "marketing-mix-modeling",
    "RecommendationsAudienceInsights": "audience-insights",
    "RecommendationsInsightsPartnerOpportunities": "partner-opportunities",
    "RecommendationsInsightsTacticalRecommendations": "tactical-recommendations",
    "RecommendationsInsightsPersonaBuilder": "persona-builder",
    "AMCAdmin": "amc-administration",
    "AMCWorkflow": "amc-workflow",
    "AMCRuleAudience": "amc-rule-audience",
    "AMCAdAudience": "amc-ad-audience",
    "AudiencesDiscovery": "audience-discovery",
    "BrandBenchmarks": "brand-benchmarks",
    "BrandMetrics": "brand-metrics",
    "AmazonAttribution": "attribution",
    "CreativesAssets": "creative-assets",
    "ChangeHistory": "change-history",
    "DataProviderData": "data-provider",
    "ProductsMetadata": "product-metadata",
    "ProductsEligibility": "product-eligibility",
    "ModerationResults": "moderation-results",
    "UnifiedPreModerationResults": "pre-moderation-results",
    "AmazonMarketingStreamSubscriptions": "ams-subscriptions",
    "Locations": "locations",
    "ExportsSnapshots": "exports-snapshots",
    "MediaPlanningReachForecasting": "reach-forecasting",
}

def main():
    # Load current packages.json
    packages_path = Path(__file__).parent.parent.parent / "openapi" / "resources" / "packages.json"
    
    with open(packages_path) as f:
        manifest = json.load(f)
    
    # Create new packages mapping with human-readable aliases as keys
    new_packages = {}
    for namespace, alias in PACKAGE_ALIASES.items():
        new_packages[alias] = namespace
    
    # Also check for any data-provider-hashed special case
    new_packages["data-provider-hashed"] = "DataProviderHashed"
    
    # Update the manifest
    manifest["packages"] = new_packages
    
    # Add the reverse mapping (aliases section)
    manifest["aliases"] = PACKAGE_ALIASES.copy()
    
    # Update groups to use human-readable aliases
    manifest["groups"] = {
        "core": ["profiles", "exports-snapshots"],
        "sponsored": ["sp", "sb-v3", "sb-v4", "sd"],
        "amc": ["amc-administration", "amc-workflow", "amc-rule-audience", "amc-ad-audience"],
        "dsp": ["dsp-mea", "dsp-adv", "dsp-aud", "dsp-con", "dsp-kpi"],
        "reporting": ["async-reports-v3", "brand-metrics", "store-analytics", "exports-snapshots", "marketing-mix-modeling"]
    }
    
    # Add a prefixes mapping for tool name generation (namespace -> short prefix)
    # This is what will be used for the actual tool names in the API
    manifest["prefixes"] = {
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
        "SPSnapshotsSuggestedKeywords": "spsugg",
        "AmazonDSPMeasurement": "dspmea",
        "AmazonDSPAdvertisers": "dspadv",
        "AmazonDSPAudiences": "dspaud",
        "AmazonDSPConversions": "dspcon",
        "AmazonDSPTargetKPIRecommendations": "dspkpi",
        "ReportingVersion3": "rpasyn",
        "StoresAnalytics": "stor",
        "ReportingMarketingMixModeling": "rpmmm",
        "RecommendationsAudienceInsights": "audins",
        "RecommendationsInsightsPartnerOpportunities": "part",
        "RecommendationsInsightsTacticalRecommendations": "tact",
        "RecommendationsInsightsPersonaBuilder": "pers",
        "AMCAdmin": "amcadm",
        "AMCWorkflow": "amcwf",
        "AMCRuleAudience": "amcrul",
        "AMCAdAudience": "amcaud",
        "AudiencesDiscovery": "aud",
        "BrandBenchmarks": "brnbm",
        "BrandMetrics": "brnmet",
        "AmazonAttribution": "attr",
        "CreativesAssets": "creat",
        "ChangeHistory": "hist",
        "DataProviderData": "dataprv",
        "DataProviderHashed": "dataprvhash",
        "ProductsMetadata": "prodm",
        "ProductsEligibility": "prode",
        "ModerationResults": "mod",
        "UnifiedPreModerationResults": "premod",
        "AmazonMarketingStreamSubscriptions": "ams",
        "Locations": "loc",
        "ExportsSnapshots": "export",
        "MediaPlanningReachForecasting": "reach",
    }
    
    # Save updated manifest
    with open(packages_path, "w") as f:
        json.dump(manifest, f, indent=2)
    
    print(f"✅ Updated packages.json with human-readable aliases")
    print(f"   Total packages: {len(new_packages)}")
    print("\nSample mappings:")
    for alias, ns in list(new_packages.items())[:5]:
        print(f"  '{alias}' -> {ns}")

if __name__ == "__main__":
    main()