rule firefox_ntuser {
    meta:
	description = "Firefox in registry"
	author = "David"
	date = "2021-04-13"
    strings:
	//$s0 = "660069007200650066006f0078002e00650078006500000014001f44471a0359723fa74489c55595fe6b30ee200000001a00eebbfe230000100090e24d373f12"
        $s1 = {66 69 72 65 66 6f 78 2e 65 78 65}
    condition:
	//$s0
	$s1
}
