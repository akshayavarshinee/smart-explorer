import sys
import json
import os
import requests
from planner_agent import planner_agent

# ✅ CATEGORY MAP (broad tourist-friendly categories → FSQ IDs)
CATEGORY_MAP = {
    'Arts and Entertainment': '4d4b7104d754a06370d81259',
    'Amusement Park': '4bf58dd8d48988d182941735',
    'Aquarium': '4fceea171983d5d06c3e9823',
    'Arcade': '4bf58dd8d48988d1e1931735',
    'Art Gallery': '4bf58dd8d48988d1e2931735',
    'Bowling Alley': '4bf58dd8d48988d1e4931735',
    'Casino': '4bf58dd8d48988d17c941735',
    'Comedy Club': '4bf58dd8d48988d18e941735',
    'Exhibit': '56aa371be4b08b9a8d573532',
    'Fair': '4eb1daf44b900d56c88a4600',
    'Gaming Cafe': '4bf58dd8d48988d18d941735',
    'General Entertainment': '4bf58dd8d48988d1f1931735',
    'Karaoke Box': '5744ccdfe4b0c0459246b4bb',
    'Laser Tag Center': '52e81612bcbc57f1066b79e6',
    'Mini Golf Course': '52e81612bcbc57f1066b79eb',
    'Movie Theater': '4bf58dd8d48988d17f941735',
    'Museum': '4bf58dd8d48988d181941735',
    'Night Club': '4bf58dd8d48988d11f941735',
    'Performing Arts Venue': '4bf58dd8d48988d1f2931735',
    'Stadium': '4bf58dd8d48988d184941735',
    'Zoo': '4bf58dd8d48988d17b941735',
    'Water Park': '4bf58dd8d48988d193941735',
    'Restaurant': '4d4b7105d754a06374d81259',
    'Cafe': '63be6904847c3692a84b9bb6',
    'Bar': '4bf58dd8d48988d116941735',
    'Hotel': '4bf58dd8d48988d1fa931735',
    'Resort': '4bf58dd8d48988d12f951735',
    'Vacation Rental': '56aa371be4b08b9a8d5734e1',
    'Park': '4bf58dd8d48988d163941735',
    'National Park': '52e81612bcbc57f1066b7a21',
    'Beach': '4bf58dd8d48988d1e2941735',
    'Historic Site': '4deefb944765f83613cdba6e',
    'Theater': '4bf58dd8d48988d137941735',
    'Event': '4d4b7105d754a06373d81259'
}


def map_interest_to_category_ids(interests):
    mapped = []
    for interest in interests:
        interest_lower = interest.lower()
        for label, cat_id in CATEGORY_MAP.items():
            if interest_lower in label.lower():
                mapped.append(cat_id)
                break
    return mapped


def researcher_agent(structured_query):
    """
    Uses structured query to fetch places from Foursquare Places API.
    """

    lat = structured_query.get("latitude")
    lon = structured_query.get("longitude")

    if not lat or not lon:
        return {"error": "No valid latitude/longitude found"}

    radius = structured_query.get("radius", 5000)
    categories = structured_query.get("categories", [])
    mapped_cats = map_interest_to_category_ids(categories)

    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer H3LQGJTBG4ULTGXXWLLVOYSZ5NQZZWCXFUDSOSSLKVH3HJV0",
        "X-Places-Api-Version": "2025-06-17"
    }

    params = {
        "ll": f"{lat},{lon}",
        "radius": radius,
        "fsq_category_ids": ",".join(mapped_cats) if mapped_cats else None,
        "min_price": structured_query.get("min_price"),
        "max_price": structured_query.get("max_price"),
        "sort": structured_query.get("sort", "RELEVANCE"),
        "limit": structured_query.get("limit", 10)
    }

    params = {k: v for k, v in params.items() if v is not None}

    url = "https://places-api.foursquare.com/places/search"
    resp = requests.get(url, headers=headers, params=params)

    if resp.status_code != 200:
        return {"error": f"Foursquare API error {resp.status_code}", "details": resp.text}

    data = resp.json()

    return {
        "city": structured_query.get("city"),
        "categories_requested": categories,
        "categories_mapped": mapped_cats,
        "places": data.get("results", [])
    }


if __name__ == "__main__":
    raw_input = sys.stdin.read()
    if raw_input.strip():
        structured_query = json.loads(raw_input)
        structured_plan = planner_agent(structured_query)
        results = researcher_agent(structured_plan)
        print(json.dumps(results))