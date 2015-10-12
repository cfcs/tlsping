all:
	ocaml pkg/build.ml native=true native-dynlink=false

clean:
	rm -r _build *.native 2>/dev/null ; true 2>/dev/null ; true

