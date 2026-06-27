import time

last_alerts = {}


def should_alert(key, cooldown=10):

    current_time = time.time()

    if key not in last_alerts:
        last_alerts[key] = current_time
        return True

    if current_time - last_alerts[key] >= cooldown:
        last_alerts[key] = current_time
        return True

    return False