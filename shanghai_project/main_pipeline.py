# Main pipeline to connect Telegram monitoring, NER, model, and order placement
import os
import asyncio

from src.ftrading.monitor.telegram_monitor import start_telegram_monitor
from src.ftrading.ner.reg_service import extract_fields
from src.ftrading.model.signal_eval import evaluate_signal
from src.ftrading.feature.feature_engineering import get_features_for_signal_row_with_limit
from src.ftrading.setting import PROJECT_ROOT
from src.ftrading.monitor.trade_alert import send_trade_alert
import pandas as pd
import logging
from ftrading.monitor.telegram_client import client


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    filename=os.path.join(PROJECT_ROOT, 'data/logs/pipeline.log'),  # Log file name
    filemode='a'              # Append mode
)

async def on_new_message(message):
    try:
        # message is a dict with keys: text, post_time, entity_id

        # Step 1: NER extraction, pass entity_id if needed
        ner_result = extract_fields(message["text"], entity_id=message["entity_id"])
        if not ner_result:
            logging.warning("NER extraction failed, returned empty, or contained forbidden words.")
            return

        # Add post_time and entity_id to ner_result for model
        ner_result["source_posted_at"] = message["post_time"]
        ner_result["entity_id"] = message["entity_id"]

        # Step 2: Feature engineering
        df = pd.DataFrame([ner_result])
        # save df with exchanges, entity_id, and source_posted_at as the filename to date folder. Check if the date folder exists, if not, create it.
        date_folder = os.path.join(PROJECT_ROOT, f"data/buffer/{message['post_time'].date()}")
        if not os.path.exists(date_folder):
            os.makedirs(date_folder)
        df.to_csv(os.path.join(date_folder, f"ner_result_{message['entity_id']}_{message['post_time']}_{ner_result['exchanges']}.csv"), index=False)


        # Step 3: Kaiko features (single row)
        kaiko_features = get_features_for_signal_row_with_limit(df.iloc[0])
        # save kaiko_features with exchanges, entity_id, and source_posted_at as the filename to date folder. Check if the date folder exists, if not, create it.
        if kaiko_features is not None and isinstance(kaiko_features, pd.DataFrame):
            if not os.path.exists(date_folder):
                os.makedirs(date_folder)
            kaiko_features.to_csv(os.path.join(date_folder, f"features_{message['entity_id']}_{message['post_time']}_{ner_result['exchanges']}.csv"), index=False)


            # Step 4: Model evaluation (pass DataFrame directly)
            logging.info(kaiko_features)
            is_signal, model_output = evaluate_signal(kaiko_features)
            if is_signal:
                await send_trade_alert(is_signal, kaiko_features, client)
                logging.info(f"Signal detected: {model_output}")
                print(f"Signal detected: {model_output}")
                print("\n\n\n")
            else:
                logging.info("No actionable signal.")
                print("No actionable signal.\n\n\n")
        else:
            logging.warning("kaiko_features is None or not a DataFrame.")

    except Exception as e:
        logging.exception(f"Error processing message: {message}")
        print("\n\n\n")

async def startup():
    await client.start()
    start_telegram_monitor(callback=on_new_message, client=client)
    await client.run_until_disconnected()

if __name__ == "__main__":
    asyncio.run(startup()) 

