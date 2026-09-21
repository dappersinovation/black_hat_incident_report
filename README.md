#linux terminal commands

git clone https://github.com/dappersinovation/black_hat_incident_report.git

cd black_hat_incident_report

python3 -m venv venv

source venv/bin/activate

pip install pandas streamlit scikit-learn

python dataset.py

streamlit run app.py


#window powershell commands

git clone https://github.com/dappersinovation/black_hat_incident_report.git

cd black_hat_incident_report

python -m venv venv

venv\Scripts\Activate.ps1

pip install pandas streamlit scikit-learn

python dataset.py

streamlit run app.py
