
## 📦 Installation

### Prerequisites

- Python 3.10+
- PostgreSQL database
- API keys for exchanges and data providers

### Setup

#### macOS/Linux
```bash
# Clone repository


# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r dev-requirements.txt
pip3 install -e .

# Configure environment
export $(cat .env | xargs)
```
