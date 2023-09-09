# static-pe-analysis

Static analysis of PE files.

*Note: Python 3.6.2 is recommended.*

### Setting up the environment

Clone the repository:

    git clone https://github.com/codepictor/static-pe-analysis.git
    cd static-pe-analysis/

Create a new virtual environment:

    # on Linux:
    python3 -m venv venv
    # on Windows:
    python -m venv venv

Activate the environment:

    # on Linux:
    source venv/bin/activate
    # on Windows:
    call venv\Scripts\activate.bat

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

