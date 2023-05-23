from cvss import CVSS2


def convert_cvssv2_vector_to_cvssv3_vector(cvssv2_vector):
    """
    Returns the CVSSv3 vector
    >>> cvssv2_vector = "AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/CDP:L/TD:H/CR:ND/IR:ND/AR:M"
    >>> cvssv3_vector = convert_cvssv2_vector_to_cvssv3_vector(cvssv2_vector)
    >>> assert cvssv3_vector == 'CVSS:3.0/AV:L/UI:N/AC:L/PR:H/C:N/I:L/A:H/S:C/E:U/RL:W/RC:X'
    """
    cvss2_metrics = CVSS2(cvssv2_vector).metrics
    cvss3_metrics = {}

    # AV (P is new)
    if cvss2_metrics.get("AV") == "L":
        # L => (L|P) (usually L)
        cvss3_metrics["AV"] = "L"

    elif cvss2_metrics.get("AV") == "A":
        # A => A
        cvss3_metrics["AV"] = "A"

    elif cvss2_metrics.get("AV") == "N":
        # N => N
        cvss3_metrics["AV"] = "N"

    # AC split into AC and UI
    cvss3_metrics["UI"] = "R"
    if cvss2_metrics["AC"] == "L":
        cvss3_metrics["AC"] = "L"
        cvss3_metrics["UI"] = "N"

    elif cvss2_metrics["AC"] == "M":
        cvss3_metrics["AC"] = "L"

    elif cvss2_metrics["AC"] == "H":
        cvss3_metrics["AC"] = "H"

    # Au => PR (needs manual optimization)
    if cvss2_metrics.get("Au") == "N":
        # N => N
        cvss3_metrics["PR"] = "N"

    elif cvss2_metrics.get("Au") == "S":
        # S => (L|H) (usually L)
        cvss3_metrics["PR"] = "L"

    elif cvss2_metrics.get("Au") == "M":
        # M => (H|L) (sometimes H)
        cvss3_metrics["PR"] = "H"

    # C, I and A
    # C => H , P => L, N => N
    for key in ["C", "I", "A"]:
        if cvss2_metrics.get(key) == "N":
            cvss3_metrics[key] = "N"
        elif cvss2_metrics.get(key) == "P":
            cvss3_metrics[key] = "H"
        elif cvss2_metrics.get(key) == "C":
            cvss3_metrics[key] = "H"

    # C:C/I:C/A:C derived by S:C
    if (
        cvss2_metrics.get("C") == "C"
        and cvss2_metrics.get("I") == "C"
        and cvss2_metrics.get("A") == "C"
    ):
        cvss3_metrics["S"] = "C"
    else:
        cvss3_metrics["S"] = "U"

    # E
    # ND => X , U => U, POC => P, F => F, H => H
    if cvss2_metrics.get("E") == "POC":
        cvss3_metrics["E"] = "P"

    elif cvss2_metrics.get("E") == "ND":
        cvss3_metrics["E"] = "X"

    elif cvss2_metrics.get("E") == "F":
        cvss3_metrics["E"] = "F"

    elif cvss2_metrics.get("E") == "H":
        cvss3_metrics["E"] = "H"

    elif cvss2_metrics.get("E") == "U":
        cvss3_metrics["E"] = "U"

    # RL
    # ND => X, OF => O, TF => T, W => W, U => U
    if cvss2_metrics.get("RL") == "ND":
        cvss3_metrics["RL"] = "X"

    elif cvss2_metrics.get("RL") == "OF":
        cvss3_metrics["RL"] = "X"

    elif cvss2_metrics.get("RL") == "TF":
        cvss3_metrics["RL"] = "P"

    elif cvss2_metrics.get("RL") == "W":
        cvss3_metrics["RL"] = "W"

    elif cvss2_metrics.get("RL") == "U":
        cvss3_metrics["RL"] = "U"

    # RC
    # C = > C, UR = > R, UC = > U, ND = > X
    if cvss2_metrics.get("RC") == "C":
        cvss3_metrics["RC"] = "C"

    elif cvss2_metrics.get("RC") == "UR":
        cvss3_metrics["RC"] = "R"

    elif cvss2_metrics.get("RC") == "UC":
        cvss3_metrics["RC"] = "U"

    elif cvss2_metrics.get("RC") == "ND":
        cvss3_metrics["RC"] = "X"

    cvssv3_vector = ""
    for k, v in cvss3_metrics.items():
        cvssv3_vector += f"/{k}:{v}"
    return "CVSS:3.0/" + cvssv3_vector[1::]
