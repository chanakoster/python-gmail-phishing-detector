def determine_risk_level(risk_results):
    print("🤔Determining risk level")

    risk_counts = {
        "high": 0,
        "low": 0,
        "very low": 0
    }

    for r in risk_results:
        risk = r["risk"].lower()
        if risk in risk_counts:
            risk_counts[risk] += 1

    print(f"📊 Risk breakdown: {risk_counts}")

    if risk_counts["high"] > 0:
        risk_level = "HIGH RISK"
    elif risk_counts["low"] > 0:
        risk_level = "LOW RISK"
    elif risk_counts["very low"] >= 2:
        risk_level = "LOW RISK"
    else:
        risk_level = "Risk not detected"

    print(f"😮Risk level: {risk_level}")
    return risk_level