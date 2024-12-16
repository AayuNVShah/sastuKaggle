import requests
from flask import Flask, request, jsonify
from rdflib import Graph, Literal, Namespace, RDF

app = Flask(__name__)

# Define namespaces for RDF
EX = Namespace("http://example.org/ontology#")
RDFS = Namespace("http://www.w3.org/2000/01/rdf-schema#")

# Load your RDF data
g = Graph()
g.parse("dataset.owl", format="xml")  # Load your OWL file

# NGINX server endpoint
NGINX_AUTH_URL = "http://10.20.24.47:3000"

@app.route('/detect', methods=['POST'])
def detect_code():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    code_snippet = data.get('codeSnippet')
  

    

    # Step 2: Execute SPARQL query to analyze the code
    try:
        query = """
        PREFIX ex: <http://example.org/ontology#>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?isMalicious
        WHERE {
            ?snippet rdf:type ex:CodeSnippet .
            ?snippet rdfs:comment ?comment .
            OPTIONAL { ?snippet ex:isMalicious ?isMalicious }
            FILTER(CONTAINS(?comment, ?codeSnippet))
        }
        """

        # Execute SPARQL query
        results = g.query(query, initBindings={'codeSnippet': Literal(code_snippet)})

        # Process query results
        is_malicious = False
        for row in results:
            if row.isMalicious is not None:
                is_malicious = int(row.isMalicious) == 1
            if is_malicious:
                break

        # If malicious, return a warning
        if is_malicious:
            return jsonify({
                "isMalicious": True,
                "message": "The provided code snippet is malicious and has been rejected."
            })

        auth_response = requests.post(
            f"{NGINX_AUTH_URL}/simple/register",
            json={'email': email, 'password': password},
            timeout=5
        )

        # If authentication fails, return error
        # if auth_response.status_code != 200:
        #     return jsonify({
        #         "error": "Authentication failed",
        #         "details": auth_response.json()
        #     }), auth_response.status_code

        # Step 3: Post the code to a Docker container or code execution endpoint
        # docker_response = requests.post(
        #     f"{NGINX_AUTH_URL}/docker/execute",  # Adjust this to your Docker endpoint
        #     json={"code": code_snippet},
        #     timeout=10
        # )

        # Return the execution result
        return jsonify({
            "isMalicious": False,
            "executionResult": "Sent to server to execute!"
        })

    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(debug=True)
