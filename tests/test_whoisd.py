#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pytest
from whoisd_rwhois.whoisd import RwhoisRequest

__author__ = "Georg Kahest"
__copyright__ = "Georg Kahest"
__license__ = "mit"

def test_RwhoisRequest():
    assert RwhoisRequest.make("nimi.ee", "test_thread") == "midagi"
    assert RwhoisRequest.status("internet.ee") == "ok (paid and in zone)"
    assert RwhoisRequest.print("name", "internet.ee") == b"name        internet.ee\n"
    assert RwhoisRequest.section("Tiitel") == b"\nTiitel\n"
