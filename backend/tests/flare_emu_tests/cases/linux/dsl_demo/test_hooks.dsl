$res = call test_add(10, 20) {
  hook test_add {
    action: write_reg reg.edi = 100
  }
}
assert $res == 120
