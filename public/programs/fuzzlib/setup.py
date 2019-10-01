from distutils.core import setup

setup(
    classifiers=[
        "Development Status :: 3.0",
        "Environment :: GUI",
        "Inteded Audience :: Developers",
        "Operating System :: Microsoft :: Windows",
        "Programming Langugage :: Python",
        "Topic :: Software Development :: Security",
        ],
      name="pylf",
      version="3.0",
      url="http://www.xophdware.com",
      packages=["pylf", "pylf.pyUniDump", "pylf.pyUniDump.Windows32bit"],
      )
