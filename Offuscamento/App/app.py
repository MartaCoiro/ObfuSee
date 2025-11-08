from flask import Flask, render_template, request, jsonify
from logic.steps import (
    offuscamento_lessicale,
    trasformazione_dati,        # ⚠️ Step 3 prima dello Step 2
    offuscamento_flusso,
    anti_debugging,
    offuscamento_crittografia,  # Step 5 – Base64 (non cifratura)
    offuscamento_aead,          # Step 6 – AEAD (chiave dal server)
    AEAD_REGISTRY
)

import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/step1', methods=['POST'])
def step1():
    codice = request.form.get("codice", "")
    linguaggio = request.form.get("linguaggio", "c")
    codice_offuscato, modifiche = offuscamento_lessicale(codice, linguaggio)
    return jsonify({"codice_offuscato": codice_offuscato, "modifiche": modifiche})

@app.route('/step2', methods=['POST'])
def step2():
    codice = request.form.get("codice", "")
    linguaggio = request.form.get("linguaggio", "c")
    codice_modificato, modifiche = offuscamento_flusso(codice, linguaggio)
    return jsonify({"codice_offuscato": codice_modificato, "modifiche": modifiche})

@app.route('/step3', methods=['POST'])
def step3():
    codice = request.form.get("codice", "")
    linguaggio = request.form.get("linguaggio", "c")
    risultato = trasformazione_dati(codice, linguaggio)
    if risultato is None:
        return jsonify({"errore": "Errore durante la trasformazione dei dati."}), 500
    codice_modificato, modifiche = risultato
    return jsonify({"codice_offuscato": codice_modificato, "modifiche": modifiche})

@app.route('/step4', methods=['POST'])
def step4():
    codice = request.form.get("codice", "")
    linguaggio = request.form.get("linguaggio", "c")
    codice_modificato, modifiche = anti_debugging(codice, linguaggio)
    return jsonify({"codice_offuscato": codice_modificato, "modifiche": modifiche})

@app.route("/step5", methods=["POST"])
def step5():
    codice = request.form.get("codice", "")
    linguaggio = request.form.get("linguaggio", "c")
    codice_modificato, modifiche = offuscamento_crittografia(codice, linguaggio)
    return jsonify({"codice_offuscato": codice_modificato, "modifiche": modifiche})

@app.route('/step6', methods=['POST'])
def step6():
    codice = request.form.get("codice", "")
    linguaggio = request.form.get("linguaggio", "c")
    codice_modificato, modifiche = offuscamento_aead(codice, linguaggio)
    return jsonify({"codice_offuscato": codice_modificato, "modifiche": modifiche})

# Endpoint key-server della demo: restituisce la chiave per un dato id
@app.route("/k", methods=["GET"])
def key_service():
    key_id = request.args.get("id", "")
    want = os.environ.get("AEAD_SERVER_TOKEN")  # opzionale
    got = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if want and got != want:
        return jsonify({"error": "unauthorized"}), 401

    key_b64 = AEAD_REGISTRY.get(key_id)
    if not key_b64:
        return jsonify({"error": "unknown id"}), 404
    return jsonify({"id": key_id, "key_b64": key_b64, "ttl": 10})

@app.route("/applica_tutti", methods=["POST"])
def applica_tutti():
    codice = request.form.get("codice", "")
    linguaggio = request.form.get("linguaggio", "c")
    string_protection = request.form.get("string_protection")  # "base64" | "aead_server" | "none"

    if string_protection not in ("base64", "aead_server", "none"):
        return jsonify({
            "needs_choice": True,
            "options": ["base64", "aead_server", "none"],
            "message": (
                "Scegli la protezione delle stringhe:\n"
                "• Base64 (non è cifratura)\n"
                "• Cifratura AEAD (chiave dal server)\n"
                "• Nessuna"
            )
        }), 400

    modifiche_totali = []

    # ⚠️ Ordine: lessicale → trasformazione dati → flusso → anti-debug → (stringhe)
    core = [
        ("Step 1 – Offuscamento lessicale", offuscamento_lessicale),
        ("Step 3 – Trasformazione dei dati", trasformazione_dati),
        ("Step 2 – Flusso di controllo", offuscamento_flusso),
        ("Step 4 – Anti-Debugging", anti_debugging),
    ]
    for nome, fn in core:
        codice, md = fn(codice, linguaggio)
        modifiche_totali.append({"descrizione": f"🔷 {nome} applicato"})
        modifiche_totali.extend(md)

    if string_protection == "base64":
        codice, md = offuscamento_crittografia(codice, linguaggio)
        modifiche_totali.append({"descrizione": "🔷 Step 5 – Offuscamento dati (Base64) applicato"})
        modifiche_totali.extend(md)
    elif string_protection == "aead_server":
        codice, md = offuscamento_aead(codice, linguaggio)
        modifiche_totali.append({"descrizione": "🔷 Step 6 – Cifratura AEAD (chiave dal server) applicato"})
        modifiche_totali.extend(md)
    else:
        modifiche_totali.append({"descrizione": "ℹ️ Nessuna protezione stringhe applicata"})

    return jsonify({"codice_offuscato": codice, "modifiche": modifiche_totali})

if __name__ == "__main__":
    app.run(debug=True)
