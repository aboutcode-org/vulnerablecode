import csv
import os

import pytest
from cvss import CVSS3

from vulnerabilities.cvss2to3 import convert_cvssv2_vector_to_cvssv3_vector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/nvd_cvss.csv")


@pytest.mark.parametrize(
    "value_cvssv3,cvssv3_vector,value_cvssv2,cvssv2_vector",
    [tuple(row) for row in csv.reader(open(TEST_DATA))],
)
def test_convert_cvssv2_to_cvssv3(value_cvssv3, cvssv3_vector, value_cvssv2, cvssv2_vector):
    computed_cvssv3_vector = CVSS3(convert_cvssv2_vector_to_cvssv3_vector(cvssv2_vector)).metrics
    expected_cvssv3_vector = CVSS3(cvssv3_vector).metrics
    assert expected_cvssv3_vector == computed_cvssv3_vector
