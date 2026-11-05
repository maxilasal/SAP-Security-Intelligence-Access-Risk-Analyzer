from sapsec.engine.values import DUMMY, AuthInstance, FieldValue, parse_requirement


def test_wildcards_prefix_range_and_specials():
    assert FieldValue("*").covers("ANY")
    assert FieldValue("*").covers("")
    assert FieldValue("Z*").covers("Z_FI") and not FieldValue("Z*").covers("SAP_FI")
    assert FieldValue("1000", "1999").covers("1500") and not FieldValue("1000", "1999").covers("2000")
    assert FieldValue("' '").covers("") and not FieldValue("' '").covers("X")
    assert not FieldValue("$BUKRS").covers("1000")
    assert FieldValue("02").covers("02") and not FieldValue("02").covers("03")


def test_subsumption():
    assert FieldValue("*").contains(FieldValue("Z*"))
    assert FieldValue("Z*").contains(FieldValue("Z_FI*"))
    assert not FieldValue("Z_FI*").contains(FieldValue("Z*"))
    assert FieldValue("1000", "2000").contains(FieldValue("1200", "1300"))
    assert not FieldValue("1000").contains(FieldValue("*"))
    a = AuthInstance("F_BKPF_BUK", "A", {"ACTVT": [FieldValue("*")], "BUKRS": [FieldValue("1*")]})
    b = AuthInstance("F_BKPF_BUK", "B", {"ACTVT": [FieldValue("01")], "BUKRS": [FieldValue("1000")]})
    assert a.subsumes(b) and not b.subsumes(a)


def test_values_from_different_instances_are_never_combined():
    i1 = AuthInstance("F_BKPF_BUK", "A1", {"ACTVT": [FieldValue("02")], "BUKRS": [FieldValue("1000")]})
    i2 = AuthInstance("F_BKPF_BUK", "A2", {"ACTVT": [FieldValue("03")], "BUKRS": [FieldValue("2000")]})
    req = parse_requirement({"object": "F_BKPF_BUK", "fields": {"ACTVT": ["02"], "BUKRS": ["2000"]}})
    assert req.matching_instances([i1, i2]) == []
    req_ok = parse_requirement({"object": "F_BKPF_BUK", "fields": {"ACTVT": ["02"], "BUKRS": ["1000"]}})
    assert req_ok.matching_instances([i1, i2]) == [i1]


def test_authority_check_with_dummy_and_missing_field():
    i = AuthInstance("S_DEVELOP", "X", {"ACTVT": [FieldValue("03")]})
    assert i.check({"ACTVT": "03", "OBJTYPE": DUMMY})
    assert not i.check({"ACTVT": "03", "OBJTYPE": "PROG"})  # campo sin valores no autoriza


def test_condition_modes():
    i = AuthInstance("S_TABU_DIS", "X", {"ACTVT": [FieldValue("03")], "DICBERCLS": [FieldValue("*")]})
    assert parse_requirement({"object": "S_TABU_DIS", "fields": {"DICBERCLS": "*"}}).matching_instances([i])
    assert not parse_requirement({"object": "S_TABU_DIS", "fields": {"ACTVT": "*"}}).matching_instances([i])
    assert parse_requirement({"object": "S_TABU_DIS", "fields": {"ACTVT": {"mode": "present"}}}).matching_instances([i])
    assert not parse_requirement({"object": "S_TABU_DIS",
                                  "fields": {"ACTVT": {"all_of": ["02", "03"]}}}).matching_instances([i])
