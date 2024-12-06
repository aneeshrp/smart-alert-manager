from flask import Flask, render_template, request, redirect, url_for, flash, get_flashed_messages
import json

app = Flask(__name__)
app.secret_key = '1a2B3c4D5e6F7g8H9i0J'

# Load configuration from JSON file
def load_config():
    with open('config.json', 'r') as config_file:
        return json.load(config_file)

# Save configuration to JSON file
def save_config(config):
    with open('config.json', 'w') as config_file:
        json.dump(config, config_file, indent=4)

@app.route('/')
def index():
    config = load_config()
    return render_template('index.html', rules=config['rules'], correlation_rules=config['correlation_rules'], time_based_rules=config.get('time_based_rules', {}))

# View Rules
@app.route('/view/rule', methods=['GET'])
def view_rules(rule_name=None):
    config = load_config()
    return render_template('view_rules.html', rules=config['rules'])


# Add/Edit Rule
@app.route('/add/rule', methods=['GET', 'POST'])
@app.route('/edit/rule/<rule_name>', methods=['GET', 'POST'])
def add_edit_rule(rule_name=None):
    if request.method == 'POST':
        rule_name = request.form['rule_name']
        condition = request.form['condition']
        severity = request.form['severity']
        
        config = load_config()
        config['rules'][rule_name] = {
            'condition': condition,
            'severity': severity,
        }
        save_config(config)
        flash(f"Rule '{rule_name}' has been successfully saved!", "success")
        return redirect(url_for('view_rules'))
    
    config = load_config()
    rule = config['rules'].get(rule_name, {})
    condition = rule.get('condition', '')
    severity = rule.get('severity', '')
    description = rule.get('description', '')

    return render_template(
        'add_edit_rule.html', 
        action='Add' if not rule_name else 'Edit', 
        rule_name=rule_name, 
        condition=condition, 
        severity=severity, 
        description=description
    )

# Delete Rule
@app.route('/delete/rule/<rule_name>')
def delete_rule(rule_name):
    config = load_config()
    config['rules'].pop(rule_name, None)
    save_config(config)
    flash(f"Rule '{rule_name}' has been successfully deleted!", "success")
    return redirect(url_for('view_rules'))


# View Rules
@app.route('/view/correlations', methods=['GET'])
def view_correlations(rule_name=None):
    config = load_config()
    return render_template('view_correlation.html', correlation_rules=config['correlation_rules'])

# Add/Edit Correlation Rule
@app.route('/add/correlation', methods=['GET', 'POST'])
@app.route('/edit/correlation/<alert_name>', methods=['GET', 'POST'])
def add_edit_correlation(alert_name=None):
    if request.method == 'POST':
        alert_name = request.form['alert_name']
        correlated_alerts = request.form['correlated_alerts'].split(',')
        config = load_config()
        config['correlation_rules'][alert_name] = correlated_alerts
        save_config(config)
        flash(f"Correlation Rule: '{alert_name}' has been successfully saved!", "success")
        return redirect(url_for('view_correlations'))
    
    config = load_config()
    correlated_alerts = config['correlation_rules'].get(alert_name, [])
    return render_template('add_edit_correlation.html', action='Add' if not alert_name else 'Edit', alert_name=alert_name, correlated_alerts=correlated_alerts)

# Delete Correlation Rule
@app.route('/delete/correlation/<alert_name>')
def delete_correlation(alert_name):
    config = load_config()
    config['correlation_rules'].pop(alert_name, None)
    save_config(config)
    flash(f"Correlation Rule: '{alert_name}' has been successfully deleted!", "success")
    return redirect(url_for('view_correlations'))

# View Rules
@app.route('/view/time', methods=['GET'])
def view_time(rule_name=None):
    config = load_config()
    return render_template('view_time.html', time_based_rules=config.get('time_based_rules', {}))

# Add/Edit Time-Based Rule
@app.route('/add/time', methods=['GET', 'POST'])
@app.route('/edit/time/<alert_name>', methods=['GET', 'POST'])
def add_edit_time(alert_name=None):
    if request.method == 'POST':
        alert_name = request.form['alert_name']
        peak_hours_start = request.form['peak_hours_start']
        peak_hours_end = request.form['peak_hours_end']
        peak_hours_threshold = request.form['peak_hours_threshold']
        
        off_hours_start = request.form['off_hours_start']
        off_hours_end = request.form['off_hours_end']
        off_hours_threshold = request.form['off_hours_threshold']

        config = load_config()
        config.setdefault('time_based_rules', {})[alert_name] = {
            'peak_hours': {
                'start': peak_hours_start,
                'end': peak_hours_end,
                'threshold': peak_hours_threshold,
            },
            'off_hours': {
                'start': off_hours_start,
                'end': off_hours_end,
                'threshold': off_hours_threshold,
            }
        }
        save_config(config)
        flash(f"Time-based Rule for '{alert_name}' has been successfully saved!", "success")
        return redirect(url_for('view_time'))
    
    config = load_config()
    time_based_rule = config.get('time_based_rules', {}).get(alert_name, {})
    
    peak_hours_start = time_based_rule.get('peak_hours', {}).get('start', '')
    peak_hours_end = time_based_rule.get('peak_hours', {}).get('end', '')
    peak_hours_threshold = time_based_rule.get('peak_hours', {}).get('threshold', '')

    off_hours_start = time_based_rule.get('off_hours', {}).get('start', '')
    off_hours_end = time_based_rule.get('off_hours', {}).get('end', '')
    off_hours_threshold = time_based_rule.get('off_hours', {}).get('threshold', '')

    return render_template('add_edit_time.html', 
                           action='Add' if not alert_name else 'Edit', 
                           alert_name=alert_name, 
                           peak_hours_start=peak_hours_start,
                           peak_hours_end=peak_hours_end,
                           peak_hours_threshold=peak_hours_threshold,
                           off_hours_start=off_hours_start,
                           off_hours_end=off_hours_end,
                           off_hours_threshold=off_hours_threshold)


# Delete Time-Based Rule
@app.route('/delete/time/<alert_name>')
def delete_time(alert_name):
    config = load_config()
    config.get('time_based_rules', {}).pop(alert_name, None)
    save_config(config)
    flash(f"Correlation Rule: '{alert_name}' has been successfully deleted!", "success")
    return redirect(url_for('view_time'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9010, debug=True)
