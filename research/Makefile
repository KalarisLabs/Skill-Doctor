all: pdf

pdf:
	pdflatex research_paper
	bibtex research_paper
	pdflatex research_paper
	pdflatex research_paper

clean:
	rm -f *.aux *.log *.out *.bbl *.blg *.pdf
