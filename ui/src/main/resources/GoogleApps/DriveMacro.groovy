{{groovy}}
def mainReference = services.model.createDocumentReference('', 'GoogleApps','OAuth')
if (!services.licensing.licensor.hasLicensureForEntity(mainReference)) {
    println """
  {{error}}{{translation key='googleapps.error.noValidLicense' /}}{{/error}}
  """
} else {
    def id = xcontext.macro.params.id;
    def width = xcontext.macro.params.width;
    def height = xcontext.macro.params.height;
    def nb = Integer.parseInt(xcontext.macro.params.nb);
    def obj = doc.getObject("GoogleApps.SynchronizedDocumentClass", nb)
    def escapetool = new org.xwiki.velocity.tools.EscapeTool();
    def force = false;
    def googleApps = services.googleApps

    if(!googleApps.active || !googleApps.driveEnabled) {
        println services.localization.render('googleapps.error.driveDisabled')
    } else {
        // adding stylesheet
        xwiki.ssx.use("GoogleApps.DriveMacro");

        if (xcontext.macro.params.authentication) {
            if (googleApps.authorize(false)) {
                def url = googleApps.getAuthorizationURL()
                println services.localization.render("googleapps.macro.maybeReqAuth", ["[[", ">>url:${url}]]"]);
            }
        }

        if (nb==null)
            nb = 0;
        def embednb = (!request.nb) ? 0 : Integer.parseInt(request.nb)
        def query = request.getParameter("query${nb}")

        if (request.update=="1" && nb==embednb)
            force = true;

        if (request.embed=="1") {
            if (embednb==nb) {
                obj = googleApps.createOrUpdateEmbedObject(request.id, doc, obj, nb);
                doc.use(obj);
            }
        }

        if (id!=null) {
            println id;
        } else if (obj!=null && !force) {
            doc.use(obj);
            def embedLink = doc.getValue("embedLink")
            def editLink = doc.getValue("editLink")
            def swidth = (width.endsWith("%")) ? width : width + "px";
            print """(% class="drive-links" style="width: ${swidth};" %)((("""
            print """[[Change>>||queryString="update=1&nb=${nb}"]]"""
            if (editLink && editLink.startsWith("http"))
                print """ - [[Edit>>url:${editLink}]]"""
            println ")))"
            println """{{html clean=false}}<iframe src="${embedLink}" width="${width}" height="${height}"></iframe>{{/html}}"""
        } else {
            def tquery = ""
            if (query)
                tquery = escapetool.xml(query)
            println """

{{translation key='googleapps.macro.mainHint'/}}

  {{html clean=false wiki=true}}
  <form action="" method="get">
  {{translation key='googleapps.macro.insert'/}}
  <input type="hidden" name="update" value="1" />
  <input type="hidden" name="nb" value="${nb}" />
  <input type="text" name="query${nb}" value="${tquery}" />
  <input type="submit" value="Search" />
  </form>
  {{/html}}
  """
            if (query && embednb==nb) {
                def squery = "'" + query + "'"
                def results = googleApps.listDriveDocuments("fullText contains ${squery}", 10)
                def nbres = results.size();

                println "${nbres} documents found: "
                for (entry in results) {
                    def docName = entry.title;
                    def embedLink = entry.embedLink;
                    if (embedLink==null)
                        embedLink = entry.alternateLink;
                    if (embedLink==null)
                        println """* ${docName}: """ + services.localization.render('googleapps.macro.canBeEmbedded')
                    else
                        println """* ${docName}: [[{{translation key='googleapps.macro.nowEmbed'/}}>>||queryString="embed=1&nb=${nb}&id=${entry.id}"]]"""
                }
            }
        }
    }
}
{{/groovy}}