"""
Explainable security decision engine.

Converts risk signals into a human-readable explanation.
"""


def generate_explanation(risk_result):
    """
    Generate a structured explanation from a risk result.
    """

    explanations = []

    for signal in risk_result.signals:

        explanations.append({
            "signal": signal.name,
            "importance": signal.weight,
            "explanation": signal.reason,
            "source": signal.source
        })

    # Highest-weight signals appear first.
    explanations.sort(
        key=lambda item: item["importance"],
        reverse=True
    )

    return {
        "risk_score": risk_result.score,
        "risk_level": risk_result.level,
        "explanations": explanations
    }


def print_explanation(explanation):
    """
    Print the explanation in a user-friendly format.
    """

    print("\n" + "=" * 60)
    print("SECURITY EXPLANATION")
    print("=" * 60)

    print(
        f"\nRisk: {explanation['risk_level']}"
    )

    print(
        f"Score: {explanation['risk_score']}/100"
    )

    print("\nWhy:")

    for item in explanation["explanations"]:

        print(
            f"\n[{item['importance']}] "
            f"{item['signal']}"
        )

        print(
            f"  {item['explanation']}"
        )

    print("\n" + "=" * 60)
