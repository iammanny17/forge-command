def lookup(conn, request):
    return conn.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")

api_key = "example_not_a_real_secret_12345"
