import pytest

from vulnerabilities.models import Curator


@pytest.mark.django_db
def test_curator_str_returns_name():
    curator = Curator.objects.create(name="John")
    assert str(curator) == "John"


@pytest.mark.django_db
def test_curator_has_no_curations_by_default():
    curator = Curator.objects.create(name="John")
    assert curator.curations.count() == 0
