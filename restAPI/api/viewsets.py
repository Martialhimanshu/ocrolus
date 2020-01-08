import re
from uuid import UUID
import pandas as pd
import logging

from restAPI.api.permissions import DataPermissions
from restAPI.models import *
from restAPI.api.models import *
from rest_framework.decorators import list_route
from rest_framework import exceptions
from rest_framework.response import Response
from rest_framework import generics as DRF_generics
from rest_framework import mixins
from rest_framework.viewsets import ViewSetMixin as DRF_ViewSetMixin
from django.db.models import Avg
from django.http import FileResponse

from restAPI.serializers import ContentSerializer

logger = logging.getLogger(__name__)

APP_SECRET_REGEX_LIST = [
    re.compile('^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', flags=re.I),
    re.compile('[a-fA-z0-9]{32}\Z', flags=re.I)
]


class GenericAPIView(DRF_generics.GenericAPIView):
    def get_object(self):
        obj = super(GenericAPIView, self).get_object()
        self.check_action_permissions(self.request, self.action, obj)
        return obj

    def check_action_permissions(self, request, action, obj=None):
        """
        Check if the request should be permitted for specified actions
        Raises an appropriate exception if the request is not permitted.
        """
        if action is None:
            self.permission_denied(request)

        for permission in self.get_permissions():
            if not permission.has_action_permission(request, self, action, obj):
                self.permission_denied(request)


class ProjectRestrictedGenericAPIView(GenericAPIView):
    def app_permission_denied(self, request, message=None):
        """
        If request is not permitted, determine what kind of exception to raise.
        """
        if not request.successful_authenticator and not message:
            raise exceptions.NotAuthenticated()
        if message:
            raise exceptions.PermissionDenied(detail=message)
        raise exceptions.PermissionDenied(detail=message)


class ViewSetMixin(DRF_ViewSetMixin):
    """
    Overrides the `check_permissions` method to provide `action` keyword
    """
    def check_action_permissions(self, request, action=None, obj=None):
        if action is None:
            action = self.action
        return super(ViewSetMixin, self).check_action_permissions(request, action=action, obj=obj)


class ProjectRestrictedViewSetMixin(ViewSetMixin):
    message = "Send the correct api-keys to access the endpoints"
    app_id_message = "Send a valid app-id to access endpoints"
    api_secret_key_message = "Send a valid api-secret-key to access endpoints"

    def app(self, request, api_obj=None):
        """
        Setting the Property to request object. So that I can access in the Viewsets.
        :returns request.app
        """
        request.app = property(lambda self: api_obj)
        return setattr(request, 'app', api_obj)

    def _validate_app_id(self, app_id):
        """
        We will check the app_id is a valid or not
        """
        try:
            uuid_hex = UUID(app_id)
            regex = APP_SECRET_REGEX_LIST[0]
            m = regex.search(app_id)
            if not m:
                return False
            elif uuid_hex or m:
                return True
        except ValueError:
            return False

    def _validate_api_secret_key(self, api_secret_key):
        """
        We will check the api_secret_key is a valid or not
        """
        regex = APP_SECRET_REGEX_LIST[1]
        m = regex.search(api_secret_key)
        if not m:
            return False
        else:
            return True

    def check_api_keys(self, request):
        """
        It will take the request object. Checks the api keys present in those request or not.
        If keys present then give access to the Project API Endpoint otherwise it raises the
        permission denied.
        :param request
        :param HTTP_APP_ID
        :param HTTP_API_SECRET_KEY
        :returns True or False
        """
        app_id, api_obj = request.META.get("HTTP_APP_ID"), None
        api_secret_key = request.META.get("HTTP_API_SECRET_KEY")
        if app_id and api_secret_key:
            # validate app_id and api_secret_key
            app_id_bool = self._validate_app_id(app_id)
            if not app_id_bool:
                return False, self.app_id_message
            api_secret_key_bool = self._validate_api_secret_key(api_secret_key)
            if not api_secret_key:
                return False, self.api_secret_key_message
            try:
                api_obj = ApiApp.objects.get(app_id=app_id, api_secret_key=api_secret_key, active=True)
                if api_obj:
                    self.app(request, api_obj)
                    return True, ''
            except ApiApp.DoesNotExist:
                self.app(request, api_obj)
                return False, self.message
        else:
            self.app(request, api_obj)
            return False, self.message


class ProjectRestrictedGenericViewSet(ProjectRestrictedViewSetMixin, ProjectRestrictedGenericAPIView):
    """
    The GenericViewSet class does not provide any actions by default,
    but does include the base set of generic view behavior, such as
    the `get_object` and `get_queryset` methods.
    """
    def initial(self, request, *args, **kwargs):
        """
        Runs anything that needs to occur prior to calling the method handler.
        """

        # It's checks the permissions for the third party endpoint or not. It give access if key present.
        bool_value, message = self.check_api_keys(request)
        if bool_value:
            super(ProjectRestrictedGenericViewSet, self).initial(request, *args, **kwargs)
            # Check action permissions
            self.check_action_permissions(request)
        else:
            self.app_permission_denied(request, message)


class ProjectRestrictedModelViewSet(mixins.CreateModelMixin,
                               mixins.ListModelMixin,
                               mixins.RetrieveModelMixin,
                               mixins.UpdateModelMixin,
                               mixins.DestroyModelMixin,
                               ProjectRestrictedGenericViewSet):
    """
        A viewset that provides default `create()`, `retrieve()`, `update()`,
        `partial_update()`, `destroy()` and `list()` actions.
        """
    pass


class DataAPIViewSet(ProjectRestrictedModelViewSet):
    queryset = PhoneBook.objects.all()
    serializer_class = PhoneBookSerializer
    permission_classes = [DataPermissions]

    @list_route(methods=['POST'])
    def search(self, request):
        """
        Search API to get content based on query value.
        endpoint: /data/search/
        type: POST
        :param: query(file): query file to find content from matching message.
        :return
            output.txt (file object): Response of search query as required in assignment.
        """
        file = self.request.data['file']
        with open(file) as f:
            content = f.readlines()
        content = [x.strip() for x in content]
        # creating a new file output.txt for storing results.
        output = open('Output.txt', 'w+')
        # write all matching results while iterating over queries item
        for query in content:
            output.write("Matches for: %s\n" % query)
            # filtering out all the exact matches from phone-book in sorted manner by first name.
            matches = self.queryset.filter(last_name__icontains=query).order_by('first_name')
            if not matches:
                output.write("No results found")
            else:
                for count, result in enumerate(matches):
                    output.write("Result {0}: {1}, {2}, {3}, {4}\n".format(
                        count, result.last_name, result.first_name, result.state, result.phone_number
                    ))
        # closing file after final iteration of all queries in a file.
        output.close()
        file_handle = output.open()
        response = FileResponse(file_handle, content_type='text/plain')
        response['Content-Length'] = file_handle.size
        response['Content-Disposition'] = 'attachment; filename="%s"' % file_handle.name
        return Response(response)

    @list_route(methods=['POST'])
    def upload_sheet(self, request):
        """
        Update entries for requested content.
        Content entries only be allowed by sheet.
        endpoint: /data/upload_sheet/
        :param:
            request (payload): Post api requested payload to upload order sheet to DB.
        :return:
        """
        file = self.request.data['file']

        # validating requested payload.
        if not file:
            return Response("Got no file! Please hit me again with file.")
        # Only .csv/xls format file are allowed
        if file.name.rsplit('.')[1] == 'csv':
            sheet_as_df = pd.read_csv(file)
        elif file.name.rsplit('.')[1] == 'xls':
            sheet_as_df = pd.read_excel(file)
        else:
            return Response("Only .csv/.xls format type allowed for now.")

        # sheet uploading code
        # =============Logic Start================
        header = ['last_name', 'first_name', 'state', 'phone_number']
        df = sheet_as_df
        if not set(header).issubset(df.columns):
            return False, f'Please check uploading sheet matching headers as: {header}'
        # filling empty(NaN) of data-frame entry with 0.0
        df = df.fillna(0)
        from itertools import islice
        batch_size = 100
        while True:
            content_instance = [Content(
                first_name=record['first_name'],
                last_name=record['last_name'],
                state=record['state'],
                phone_number=record['phone_number']
            ) for record in islice(df.to_dict('records'), batch_size)]
            if not content_instance:
                logger.info('Unable to update PhoneBook model with entries.')
                break
            PhoneBook.objects.bulk_create(content_instance, batch_size)
        # =============Logic End==================

        return Response('Successfully updated order entry!')

