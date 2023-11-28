from client import Client
from controller import Controller
from view import View


def main():
    client = Client()
    view = View()
    controller = Controller(view, client)
    controller.run_view()
    client.client_close()


if __name__ == "__main__":
    main()
