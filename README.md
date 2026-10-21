# NCEC custom Open edX API

This package supplies the APIs used by the Admin and Learner portals.
The R1 repair restores the working source from the saved staging LMS.
The active package files match production too. The course-creator removal
request continues to use `settings.CMS_ROOT_URL` instead of a production URL.

Run the regression checks with `python3 -m unittest discover -s tests -v`.
These checks replace database and Open edX service boundaries with fixtures.
Also test the real Django routes and public course page in an isolated image
and on staging before accepting a release. Do not exercise deletion or grade
completion against live users merely to test the build.
