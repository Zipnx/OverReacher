
build: clean 
	python3 setup.py sdist bdist_wheel
	python3 -m twine check dist/*

clean:
	rm -rf build dist *.egg-info
