global xTab :table[addr] of set[string];

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	if (to_lower(name) == "user-agent")
	{
		if(c$id$orig_h !in xTab)
		{
			xTab[c$id$orig_h] = set(value);
		}
		else
		{
			add xTab[c$id$orig_h][value];
		}
	}
}

event zeek_done()
{
	for (i in xTab)
	{
		if(|xTab[i]| >= 3)
		{
			print fmt("%s is a proxy", i);
		}
	}
}
