# static-pe-analysis

Static analysis of PE files.

*Note: Python 3.6 is required.*

### Setting up the environment

Clone the repository:

    git clone https://github.com/codepictor/static-pe-analysis.git
    cd static-pe-analysis/

Create a new virtual environment:

    <path to python3.6> -m venv venv

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

Finally, run *main.py*:

    python src/main/python/main.py
