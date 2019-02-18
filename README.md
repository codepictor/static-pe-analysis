## How to deploy it:

First of all, you should have ```python 3.x``` and ```git``` in your PATH variable to work with this project.

*Note for Windows users*: You should start a command line with administrator's privileges. 

Clone the repository:

    git clone https://github.com/codepictor/static-pe-analysis.git
    cd static-pe-analysis/

Create a new virtual environment:

    # on Linux:
    python3 -m venv peenv
    # on Windows:
    python -m venv peenv

Activate the environment:

    # on Linux:
    source peenv/bin/activate
    # on Windows:
    call peenv\Scripts\activate.bat

Install required dependencies:

    # on Linux:
    pip install --upgrade pip -r requirements.txt
    # on Windows:
    python -m pip install --upgrade pip -r requirements.txt

Finally, run *src/main.py*:

    # on Linux:
    python3 src/static_pe_analyzer.py <path to a single PE file or a folder>
    # on Windows:
    python src\static_pe_analyzer.py <path to a single PE file or a folder>

