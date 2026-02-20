option trace = true
$bad_input = alloc("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
call vuln_strcpy($bad_input)
