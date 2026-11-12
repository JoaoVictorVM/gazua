import pytest
from hypothesis import given
from hypothesis import strategies as st

from gazua.reports.terminal import clean_terminal, safe_line

ESC = "\x1b"


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        (f"{ESC}[31mred{ESC}[0m", "red"),
        (f"{ESC}[2J{ESC}[Hclear", "clear"),
        (f"{ESC}]8;;https://evil.example{ESC}\\link{ESC}]8;;{ESC}\\", "link"),
        (f"{ESC}]52;c;ZXZpbA=={ESC}\\after", "after"),
        (f"{ESC}]0;title\x07after", "after"),
        (f"{ESC}Pq#0;2;0;0;0{ESC}\\after", "after"),
        ("\x9b31mred\x9b0m", "red"),
        ("\x9d0;title\x9cafter", "after"),
        ("\x90payload\x9cafter", "after"),
        ("over\rwrite", "overwrite"),
        ("back\x08space", "backspace"),
        ("bell\x07", "bell"),
        (f"{ESC}7save{ESC}8", "save"),
        ("keep\ttab\nline", "keep\ttab\nline"),
    ],
)
def test_strips_csi_osc_dcs_and_c1(raw: str, shown: str) -> None:
    assert clean_terminal(raw) == shown


@pytest.mark.parametrize(
    "raw",
    [
        f"start{ESC}[",
        f"start{ESC}]52;c;ZXZpbA==",
        f"start{ESC}P unterminated",
        f"start{ESC}",
        "start\x9b",
        "start\x9d0;title",
    ],
)
def test_split_and_unterminated_controls_are_neutralized(raw: str) -> None:
    cleaned = clean_terminal(raw)

    assert cleaned.startswith("start")
    assert ESC not in cleaned
    assert "52;c" not in cleaned
    assert all(char.isprintable() or char in "\n\t" for char in cleaned)


@given(st.text())
def test_cleaned_text_has_no_controls(value: str) -> None:
    cleaned = clean_terminal(value)

    assert ESC not in cleaned
    assert not any(0x80 <= ord(char) <= 0x9F for char in cleaned)
    assert all(char in "\n\t" or ord(char) >= 0x20 for char in cleaned)
    assert "\n" not in safe_line(value)
