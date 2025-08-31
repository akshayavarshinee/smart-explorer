import sys
import json
import requests

def geocode_city(city_name):
    """
    Use OpenStreetMap Nominatim to convert city/hotel name → lat/lon
    """
    url = "https://nominatim.openstreetmap.org/search"
    params = {
        "q": city_name,
        "format": "json",
        "limit": 1
    }
    headers = {
        "User-Agent": "SmartExplorer/1.0 (smart.explorer.hats@gmail.com)"  # Nominatim requires this
    }

    resp = requests.get(url, params=params, headers=headers)
    if resp.status_code == 200 and resp.json():
        loc = resp.json()[0]
        return float(loc["lat"]), float(loc["lon"])
    return None, None


def planner_agent(user_form_input):
    """
    Normalize raw user form input into a structured query
    for the researcher agent.
    """

    city = user_form_input.get("city")
    lat = user_form_input.get("latitude")
    lon = user_form_input.get("longitude")

    # If no lat/lon given → geocode from city/hotel name
    if (not lat or not lon) and city:
        lat, lon = geocode_city(city)

    structured = {
        "city": city,
        "latitude": lat,
        "longitude": lon,
        "radius": user_form_input.get("radius", 5000),  # default 5 km
        "min_price": user_form_input.get("min_price"),
        "max_price": user_form_input.get("max_price"),
        "sort": user_form_input.get("sort", "RELEVANCE"),  # default relevance
        "limit": user_form_input.get("limit", 10),         # default 10 results
        "categories": user_form_input.get("categories", [])
    }

    return structured


if __name__ == "__main__":
    raw_input = sys.stdin.read()
    if raw_input.strip():
        user_form_input = json.loads(raw_input)
        structured = planner_agent(user_form_input)
        print(json.dumps(structured))  # ✅ only JSON output
