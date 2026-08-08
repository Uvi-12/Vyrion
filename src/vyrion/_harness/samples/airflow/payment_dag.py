"""Sample Airflow DAG with a human-in-the-loop approval gating a protected task."""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.standard.operators.hitl import HITLOperator
from datetime import datetime


def transfer_funds(**context):
    # protected action; reads the approval decision from XCom / Variable
    approval = context["ti"].xcom_pull(task_ids="request_approval", key="approval")
    if approval == "approve":
        return "executed"
    return "blocked"


with DAG("payment_pipeline", start_date=datetime(2026, 1, 1), schedule=None) as dag:
    request_approval = HITLOperator(
        task_id="request_approval",
        subject="Approve wire transfer",
        options=["approve", "reject"],
    )
    execute = PythonOperator(task_id="transfer_funds", python_callable=transfer_funds)
    request_approval >> execute
