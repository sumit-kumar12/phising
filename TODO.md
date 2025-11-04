# TODO: Enhance Phishing Detection with Advanced Heuristics and ML

## Steps to Complete

- [x] Add new advanced heuristic functions in src/utils.py (e.g., domain length ratios, SSL cert age checks, subdomain suspicion)
- [x] Expand extract_features function to include new ML features (e.g., subdomain count, cert age, vowel/consonant ratio)
- [x] Create training_data.json with expanded dataset (more legitimate and phishing domains)
- [x] Modify train_ml_model to load training data from training_data.json
- [x] Retrain the ML model with new data and features
- [x] Update score_domain function to incorporate new heuristics and improved ML prediction
- [x] Test the enhanced detection on sample URLs
- [x] Fix PDF generation error by changing font to Helvetica
