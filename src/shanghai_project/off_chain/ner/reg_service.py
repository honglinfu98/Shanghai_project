import re
FORBIDDEN_WORDS = ["in"]

def extract_fields(message, entity_id=None):
    for word in FORBIDDEN_WORDS:
        # Use word boundaries to avoid partial matches
        if re.search(rf"\b{re.escape(word)}\b", message, re.IGNORECASE):
            return 
        else:
            entity_id_str = str(entity_id)
            if entity_id_str == "-1001441802238":
                try:
                    # Exchange is the first line (word before newline)
                    exchange = re.search(r"^([A-Z]+)", message)
                    
                    # Commodity/Base_commodity is in the format BASE_COMMODITY
                    base_and_commodity = re.search(r"([A-Z0-9]+)_([A-Z0-9]+)", message)
                    if base_and_commodity:
                        base_commodity, commodity = base_and_commodity.groups()
                    else:
                        base_commodity = commodity = None

                    # Entry price (Ask)
                    entry_zone = re.search(r"Ask:\s*([0-9.eE+-]+)", message)
                    entry_price_range = [entry_zone.group(1)] if entry_zone else None

                    # Target prices
                    target_prices = re.findall(r"Target:\s*([0-9.eE+-]+)", message)

                    # Stop loss (SL)
                    stop_loss = re.search(r"SL:\s*([-0-9.eE+%]+)", message)
                    # It can be a percentage or a price. Here, just return as string.

                    return {
                        "commodity": commodity,
                        "exchanges": exchange.group(1) if exchange else None,
                        "base_commodity": base_commodity,
                        "entry_price_range": entry_price_range,
                        "target_prices": target_prices if target_prices else None,
                        "stop_loss": stop_loss.group(1) if stop_loss else None,
                        "entity_id": entity_id,
                        "message_text": message,
                    }
                except Exception as e:
                    print(f"Error extracting from message: {e}")
                    return None
            elif entity_id_str == "-1001343688547":
                try:
                    # Commodity and exchange
                    commodity = re.search(r'BUY\s+#([A-Z0-9]+)/[A-Z0-9]+\s+at', message, re.IGNORECASE)
                    exchange = re.search(r'at\s+#([A-Z0-9]+)', message, re.IGNORECASE)
                    base_commodity = re.search(r'BUY\s+#(?:[A-Z0-9]+)/([A-Z0-9]+)\s+at', message, re.IGNORECASE)
                    
                    # Entry Zone: handle variations like Entry Zone: `val` - `val` or Entry: val - val
                    entry_zone = re.search(
                        r'(?:Entry(?:\s+Zone)?):\s*`?([0-9.eE+-]+)`?\s*-\s*`?([0-9.eE+-]+)`?', message)
                    
                    # Targets: 🎯 Target 1: `val` (optional %) or 🎯 Target 1: val
                    target_prices = re.findall(
                        r'🎯\s*Target\s*\d+:\s*`?([0-9.eE+-]+)`?', message)
                    if not target_prices:
                        # fallback: handle Target without emoji or without backticks
                        target_prices = re.findall(
                            r'Target\s*\d+:\s*`?([0-9.eE+-]+)`?', message)

                    # Stop loss: 🚫 Stop loss: `val` or Stop loss: val or Stop: val
                    stop_loss = re.search(
                        r'(?:Stop(?:\s+loss)?):\s*`?([0-9.eE+-]+)`?', message, re.IGNORECASE)
                    
                    return {
                        "commodity": commodity.group(1) if commodity else None,
                        "exchanges": exchange.group(1) if exchange else None,
                        "base_commodity": base_commodity.group(1) if base_commodity else None,
                        "entry_price_range": [entry_zone.group(1), entry_zone.group(2)] if entry_zone else None,
                        "target_prices": target_prices,
                        "stop_loss": stop_loss.group(1) if stop_loss else None,
                        "entity_id": entity_id,
                        "message_text": message,
                    }
                except Exception as e:
                    print(f"Error extracting from message: {e}")
                    return None
            else:
                return None



