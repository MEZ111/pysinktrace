def search(request, cursor):
    query = request.args.get("q")
    statement = "SELECT * FROM documents WHERE title = '" + query + "'"
    cursor.execute(statement)
