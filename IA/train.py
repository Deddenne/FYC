import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import precision_score, recall_score, f1_score
import joblib

# Chargement des données
data = pd.read_csv("network_traffic.csv")

# Séparer les caractéristiques (X) et la cible (y)
X = data[['ip_count', 'packet_rate']]  # Nombre de connexions et taux de paquets
y = data['is_ddos']  # 0 = normal, 1 = attaque

# Division en ensembles d'entraînement et de test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Entraînement du modèle
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Prédictions sur l'ensemble de test
y_pred = model.predict(X_test)

# Calcul des métriques
accuracy = model.score(X_test, y_test)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

# Affichage des résultats
print(f"Exactitude (Accuracy): {accuracy:.2f}")
print(f"Précision (Precision): {precision:.2f}")
print(f"Rappel (Recall): {recall:.2f}")
print(f"F1-score: {f1:.2f}")

# Validation croisée (cross-validation) pour évaluer le modèle sur plusieurs plis
cross_val_scores = cross_val_score(model, X, y, cv=5)  # 5 plis de validation croisée
print(f"Scores de la validation croisée: {cross_val_scores}")
print(f"Score moyen de la validation croisée: {cross_val_scores.mean():.2f}")

# Sauvegarde du modèle
joblib.dump(model, "ddos_detector_model.pkl")
