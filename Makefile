
build: clean 
	python3 -m build
	python3 -m twine check dist/*

clean:
	rm -rf build dist *.egg-info
