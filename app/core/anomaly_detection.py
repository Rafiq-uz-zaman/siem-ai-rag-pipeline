def detect_spike(current_count, historical_avg):
    if historical_avg == 0:
        return False

    return current_count > (historical_avg * 2)