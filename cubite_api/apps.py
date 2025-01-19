from django.apps import AppConfig
from openedx.core.djangoapps.plugins.constants import (
    ProjectType, SettingsType, PluginURLs, PluginSettings
)


class CubiteAPIsConfig(AppConfig):
    """
    Configuration for Cubite APIs.
    """

    name = 'cubite_api'
    verbose_name = 'Cubite APIs'

    plugin_app = {
        PluginURLs.CONFIG: {
            ProjectType.LMS: {
                PluginURLs.NAMESPACE: 'cubite_api',
                PluginURLs.REGEX: r'^cubite/api/v1/',
                PluginURLs.RELATIVE_PATH: 'urls',
            }
        },
        PluginSettings.CONFIG: {
            ProjectType.LMS: {
                SettingsType.COMMON: {
                    PluginSettings.RELATIVE_PATH: 'settings.common'
                },
            }
        }
    }