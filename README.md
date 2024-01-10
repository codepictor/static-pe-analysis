# static-pe-analysis

Static analysis of PE files.

*Note: Python 3.6 is required.*

### Setting up the environment

Clone the repository:

    git clone https://github.com/codepictor/static-pe-analysis.git
    cd static-pe-analysis/

Create a new virtual environment:

    <your python3.6> -m venv venv

Activate the environment:

    # Linux:
    source venv/bin/activate
    # Windows:
    call venv\Scripts\activate.bat

Install required dependencies:

    # Linux:
    pip install --upgrade pip -r requirements.txt
    # Windows:
    python -m pip install --upgrade pip -r requirements.txt

Finally, run the following:

    # GUI
    python src/main/python/main.py
    # CLI
    python src/main/python/cli_main.py <path to a PE file or a directory>
