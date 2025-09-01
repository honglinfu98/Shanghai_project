# Define the columns expected by the model
training_columns = [
    "position", "source_posted_at_dt", "source_posted_at_hour", "source_posted_at_hour_sin", "source_posted_at_hour_cos", "commodity", "exchanges", "entity_id", 
    "message_text", "base_commodity", "entry_price_range_mean", "target_prices_mean", "stop_loss_num",
    # "min_price", "max_price", "avg_price", "median_price", "std_price", "avg_trade_size_bc", "avg_trade_size_c", "max_trade_size_bc", "max_trade_size_c",
    # "median_trade_size_bc", "median_trade_size_c", "min_trade_size_bc", "min_trade_size_c",
    # "std_trade_size_bc", "std_trade_size_c", "total_trades", "total_volume_bc", "total_volume_c",
    # Kaiko engineered features
    # Returns
    "return1h", "return3h", "return12h", "return24h", "return36h", "return48h", "return60h", "return72h",
    # Volumes
    "volumefrom1h", "volumefrom3h", "volumefrom12h", "volumefrom24h", "volumefrom36h", "volumefrom48h", "volumefrom60h", "volumefrom72h",
    # Counts
    "count1h", "count3h", "count12h", "count24h", "count36h", "count48h", "count60h", "count72h",
    # Return volatility
    "returnvola3h", "returnvola12h", "returnvola24h", "returnvola36h", "returnvola48h", "returnvola60h", "returnvola72h",
    # Volume volatility
    "volumefromvola3h", "volumefromvola12h", "volumefromvola24h", "volumefromvola36h", "volumefromvola48h", "volumefromvola60h", "volumefromvola72h",
    # Count volatility
    "countvola3h", "countvola12h", "countvola24h", "countvola36h", "countvola48h", "countvola60h", "countvola72h",
    # Last price before pump
    "last_price", "marketcap", "circulating_supply", "btc_ma20", "btc_ma50", "btc_marketcap", "btc_ma20_div_ma50",
]


training_columns_nomarket = [
    "position", "source_posted_at_dt", "source_posted_at_hour", "source_posted_at_hour_sin", "source_posted_at_hour_cos", "commodity", "exchanges", "entity_id", 
    "message_text", "base_commodity", "entry_price_range_mean", "target_prices_mean", "stop_loss_num",
    # "min_price", "max_price", "avg_price", "median_price", "std_price", "avg_trade_size_bc", "avg_trade_size_c", "max_trade_size_bc", "max_trade_size_c",
    # "median_trade_size_bc", "median_trade_size_c", "min_trade_size_bc", "min_trade_size_c",
    # "std_trade_size_bc", "std_trade_size_c", "total_trades", "total_volume_bc", "total_volume_c",
    # # Kaiko engineered features
    # # Returns
    # "return1h", "return3h", "return12h", "return24h", "return36h", "return48h", "return60h", "return72h",
    # # Volumes
    # "volumefrom1h", "volumefrom3h", "volumefrom12h", "volumefrom24h", "volumefrom36h", "volumefrom48h", "volumefrom60h", "volumefrom72h",
    # # Counts
    # "count1h", "count3h", "count12h", "count24h", "count36h", "count48h", "count60h", "count72h",
    # # Return volatility
    # "returnvola3h", "returnvola12h", "returnvola24h", "returnvola36h", "returnvola48h", "returnvola60h", "returnvola72h",
    # # Volume volatility
    # "volumefromvola3h", "volumefromvola12h", "volumefromvola24h", "volumefromvola36h", "volumefromvola48h", "volumefromvola60h", "volumefromvola72h",
    # # Count volatility
    # "countvola3h", "countvola12h", "countvola24h", "countvola36h", "countvola48h", "countvola60h", "countvola72h",
    # # Last price before pump
    # "last_price",
]