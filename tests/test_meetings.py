from screenshield.integrations.meetings import MeetingDetector


def test_instantiates():
    m = MeetingDetector()
    assert m is not None


def test_active_platform_returns_none_or_string():
    m = MeetingDetector()
    result = m.active_platform()
    assert result is None or isinstance(result, str)


def test_is_sharing_bool():
    m = MeetingDetector()
    assert isinstance(m.is_sharing(), bool)
