"""Unit tests verifying state_class configuration on JellyHA numeric sensors (Issue #69)."""
import unittest
import tests.ha_mock  # Load HA mock environment

from homeassistant.components.sensor import SensorStateClass
from custom_components.jellyha.sensor import (
    JellyHALibrarySensor,
    JellyHAFavoritesCountSensor,
    JellyHAUnwatchedCountSensor,
    JellyHAUnwatchedMoviesSensor,
    JellyHAUnwatchedSeriesSensor,
    JellyHAUnwatchedEpisodesSensor,
    JellyHAWatchedCountSensor,
    JellyHAWatchedEpisodesSensor,
    JellyHAWatchedSeriesSensor,
    JellyHAWatchedMoviesSensor,
    JellyHAMoviesCountSensor,
    JellyHASeriesCountSensor,
    JellyHAEpisodesCountSensor,
    JellyHAActiveSessionsSensor,
    JellyHAConnectedClientsSensor,
    JellyHATranscodingSessionsSensor,
    JellyHAMediaStorageFreeSensor,
    JellyHALiveTVChannelsSensor,
    JellyHAMediaStorageFreePercentSensor,
    JellyHAMoviesPercentageSensor,
    JellyHASeriesPercentageSensor,
    JellyHAEpisodesPercentageSensor,
    JellyHALibraryStorageSensor,
)


class TestSensorStateClasses(unittest.TestCase):
    """Test that all numeric count, session, percentage, and storage sensors define SensorStateClass.MEASUREMENT."""

    def test_count_sensors_have_measurement_state_class(self):
        """Verify issue #69: count sensors define SensorStateClass.MEASUREMENT so HA charts them as graphs."""
        count_sensor_classes = [
            JellyHALibrarySensor,
            JellyHAFavoritesCountSensor,
            JellyHAUnwatchedCountSensor,
            JellyHAUnwatchedMoviesSensor,
            JellyHAUnwatchedSeriesSensor,
            JellyHAUnwatchedEpisodesSensor,
            JellyHAWatchedCountSensor,
            JellyHAWatchedEpisodesSensor,
            JellyHAWatchedSeriesSensor,
            JellyHAWatchedMoviesSensor,
            JellyHAMoviesCountSensor,
            JellyHASeriesCountSensor,
            JellyHAEpisodesCountSensor,
            JellyHAActiveSessionsSensor,
            JellyHAConnectedClientsSensor,
            JellyHATranscodingSessionsSensor,
        ]

        for sensor_cls in count_sensor_classes:
            with self.subTest(sensor=sensor_cls.__name__):
                self.assertEqual(
                    getattr(sensor_cls, "_attr_state_class", None),
                    SensorStateClass.MEASUREMENT,
                    f"{sensor_cls.__name__} must define _attr_state_class = SensorStateClass.MEASUREMENT",
                )

    def test_storage_and_percentage_sensors_have_measurement_state_class(self):
        """Verify storage and percentage sensors also define SensorStateClass.MEASUREMENT."""
        measurement_sensor_classes = [
            JellyHAMediaStorageFreeSensor,
            JellyHALiveTVChannelsSensor,
            JellyHAMediaStorageFreePercentSensor,
            JellyHAMoviesPercentageSensor,
            JellyHASeriesPercentageSensor,
            JellyHAEpisodesPercentageSensor,
            JellyHALibraryStorageSensor,
        ]

        for sensor_cls in measurement_sensor_classes:
            with self.subTest(sensor=sensor_cls.__name__):
                self.assertEqual(
                    getattr(sensor_cls, "_attr_state_class", None),
                    SensorStateClass.MEASUREMENT,
                    f"{sensor_cls.__name__} must define _attr_state_class = SensorStateClass.MEASUREMENT",
                )


if __name__ == "__main__":
    unittest.main()
