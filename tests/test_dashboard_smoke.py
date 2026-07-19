"""
Smoke test proving the pytest fixture harness can import dashboard.py and
run build_html() end-to-end against fixture data, with zero production
filesystem side effects. This is the foundation the Epic 1/Epic 2 story
tests build on.
"""


def test_build_html_returns_full_page(dashboard):
    html = dashboard.build_html()

    assert isinstance(html, str)
    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html


def test_build_html_contains_all_seven_screens(dashboard):
    html = dashboard.build_html()

    for screen_id in [
        "screen-overview",
        "screen-ia",
        "screen-security",
        "screen-performance",
        "screen-timeline",
        "screen-infra",
        "screen-workbench",
    ]:
        assert screen_id in html, f"missing {screen_id}"
