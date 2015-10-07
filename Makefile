client:
	ocamlfind ocamlopt -package ctypes,tls,rresult -linkpkg \
		generate_ping.ml \
	  -o tls-ping-client

clean:
	rm *.o *.cmx *.cmo *.cmi \
		tls-ping-client \
		2>/dev/null ; true
