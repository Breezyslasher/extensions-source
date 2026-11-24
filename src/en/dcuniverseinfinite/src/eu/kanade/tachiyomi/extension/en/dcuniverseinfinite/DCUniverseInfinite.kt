package eu.kanade.tachiyomi.extension.en.dcuniverseinfinite

import android.content.SharedPreferences
import android.graphics.BitmapFactory
import android.util.Base64
import android.webkit.CookieManager
import androidx.preference.EditTextPreference
import androidx.preference.PreferenceScreen
import androidx.preference.SwitchPreferenceCompat
import eu.kanade.tachiyomi.network.GET
import eu.kanade.tachiyomi.network.POST
import eu.kanade.tachiyomi.source.ConfigurableSource
import eu.kanade.tachiyomi.source.model.Filter
import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.model.MangasPage
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import eu.kanade.tachiyomi.source.online.HttpSource
import keiyoushi.utils.firstInstanceOrNull
import keiyoushi.utils.getPreferencesLazy
import keiyoushi.utils.parseAs
import keiyoushi.utils.tryParse
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import okhttp3.Headers
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

class DCUniverseInfinite :
    HttpSource(),
    ConfigurableSource {

    override val name = "DC Universe Infinite"
    override val baseUrl = "https://www.dcuniverseinfinite.com"
    override val lang = "en"
    override val supportsLatest = true

    private val apiUrl = "$baseUrl/api"

    private val preferences: SharedPreferences by getPreferencesLazy()

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.ROOT).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }
    private val dateFormatDay = SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    override val client = network.cloudflareClient.newBuilder()
        .addInterceptor { chain ->
            var request = chain.request()
            if (request.url.host == apiUrl.toHttpUrl().host) {
                val token = sessionToken()
                if (token.isNotEmpty()) {
                    val b = request.newBuilder()
                    if (request.header("Authorization").isNullOrEmpty()) {
                        b.header("Authorization", "Token $token")
                    }
                    if (request.header("Cookie")?.contains("session=") != true) {
                        val existing = request.header("Cookie")
                        val combined = if (existing.isNullOrEmpty()) "session=$token" else "$existing; session=$token"
                        b.header("Cookie", combined)
                    }
                    request = b.build()
                }
            }
            val response = chain.proceed(request)
            if (response.code == 401 || response.code == 403) {
                val host = request.url.host
                val path = request.url.encodedPath
                if (host == apiUrl.toHttpUrl().host &&
                    request.url.pathSegments.any { it == "rights" || it == "download" }
                ) {
                    response.close()
                    throw IOException("${authErrorMessage()} [HTTP ${response.code} at $path; ${tokenState()}]")
                }
                if (host == READER_HOST) {
                    response.close()
                    throw IOException(
                        "Image blocked (HTTP ${response.code}) at $path. The signed image URL was " +
                            "rejected or expired; ${tokenState()}.",
                    )
                }
            }
            response
        }
        .build()

    override fun headersBuilder(): Headers.Builder = super.headersBuilder()
        .set("Referer", "$baseUrl/")
        .set("Origin", baseUrl)
        .set("x-consumer-key", CONSUMER_KEY)

    init {
        // Remove credentials saved by an earlier test build that tried password login.
        preferences.edit()
            .remove(LEGACY_PREF_EMAIL)
            .remove(LEGACY_PREF_PASSWORD)
            .remove(LEGACY_PREF_LOGIN_TOKEN)
            .apply()
    }

    // Auth

    // Prefer a manually pasted token; otherwise read the (HttpOnly) session cookie that
    // WebView login stored. The native CookieManager can read HttpOnly cookies; only
    // JavaScript is blocked from them. This lets WebView login work with no copy-paste.
    private fun sessionToken(): String {
        val pasted = preferences.getString(PREF_SESSION_COOKIE, "").orEmpty().trim()
        if (pasted.isNotEmpty()) return pasted
        return webViewSessionCookie()
    }

    private fun webViewSessionCookie(): String = try {
        CookieManager.getInstance().getCookie(baseUrl).orEmpty()
            .split(";")
            .firstOrNull { it.trim().startsWith("session=") }
            ?.substringAfter("session=")
            ?.trim()
            .orEmpty()
    } catch (_: Exception) {
        ""
    }

    private fun tokenState(): String {
        val pasted = preferences.getString(PREF_SESSION_COOKIE, "").orEmpty().trim()
        val wv = webViewSessionCookie()
        return when {
            pasted.isNotEmpty() -> "using pasted token (${pasted.length} chars)"
            wv.isNotEmpty() -> "using WebView session cookie (${wv.length} chars)"
            else -> "no session found"
        }
    }

    private fun authErrorMessage(): String {
        if (sessionToken().isEmpty()) {
            return "Not logged in. Tap the WebView button on this source and sign in to " +
                "dcuniverseinfinite.com (solve the captcha), then reopen the chapter."
        }
        return "Your session has expired. Open WebView, sign in again, then reopen the chapter " +
            "(or paste a fresh 'session' cookie value in Settings)."
    }

    override fun setupPreferenceScreen(screen: PreferenceScreen) {
        EditTextPreference(screen.context).apply {
            key = PREF_SESSION_COOKIE
            title = "Session cookie (optional)"
            summary = "Usually not needed — just log in with the WebView button. " +
                "Only paste a 'session' cookie value here to override WebView login."
            setDefaultValue("")
            dialogTitle = "Session cookie value"
        }.also(screen::addPreference)
        SwitchPreferenceCompat(screen.context).apply {
            key = PREF_HIDE_LOCKED
            title = "Hide chapters you can't read"
            summary = "Hide issues that need a subscription your account doesn't have. " +
                "Checks each issue, so chapter lists load slower."
            setDefaultValue(false)
        }.also(screen::addPreference)
        SwitchPreferenceCompat(screen.context).apply {
            key = PREF_DEBUG
            title = "Debug: show image size report"
            summary = "Instead of opening an issue, show which preview image sizes the server returned. " +
                "Contains no login details. Turn off to read."
            setDefaultValue(false)
        }.also(screen::addPreference)
    }

    // Popular

    override fun popularMangaRequest(page: Int): Request = searchRequest(page, null, "first_released", "desc")

    override fun popularMangaParse(response: Response): MangasPage = parseSeriesList(response)

    // Latest

    override fun latestUpdatesRequest(page: Int): Request = searchRequest(page, null, "first_released", "desc")

    override fun latestUpdatesParse(response: Response): MangasPage = parseSeriesList(response)

    // Search

    override fun searchMangaRequest(page: Int, query: String, filters: FilterList): Request {
        val sort = filters.firstInstanceOrNull<SortFilter>()?.selected ?: SORTS[0]
        return searchRequest(page, query.ifBlank { null }, sort.field, sort.direction, filters)
    }

    override fun searchMangaParse(response: Response): MangasPage = parseSeriesList(response)

    private fun searchRequest(
        page: Int,
        query: String?,
        sortField: String,
        sortDirection: String,
        filters: FilterList = FilterList(),
    ): Request {
        val filterEntries = buildList {
            filters.firstInstanceOrNull<EraFilter>()?.selectedValue?.takeIf { it.isNotEmpty() }
                ?.let { add(""""eras":${it.jsonStr()}""") }
            filters.firstInstanceOrNull<FormatFilter>()?.selectedValue?.takeIf { it.isNotEmpty() }
                ?.let { add(""""art_style_tags":${it.jsonStr()}""") }
            filters.firstInstanceOrNull<CharacterFilter>()?.state?.trim()?.takeIf { it.isNotEmpty() }
                ?.let { add(""""character_tags":${it.jsonStr()}""") }
            filters.firstInstanceOrNull<ImprintFilter>()?.state?.trim()?.takeIf { it.isNotEmpty() }
                ?.let { add(""""imprints":${it.jsonStr()}""") }
        }
        val seriesFilters = "{" + filterEntries.joinToString(",") + "}"
        val body = buildString {
            append("{")
            append(""""page":$page,""")
            append(""""per_page":$PER_PAGE,""")
            append(""""document_types":["comicseries"],""")
            if (!query.isNullOrBlank()) {
                append(""""q":${query.jsonStr()},""")
            }
            append(""""filters":{"comicseries":$seriesFilters},""")
            append(""""sort_field":{"comicseries":${sortField.jsonStr()}},""")
            append(""""sort_direction":{"comicseries":${sortDirection.jsonStr()}},""")
            append(""""apply_transform":true""")
            append("}")
        }
        return POST(
            "$apiUrl/search_proxy/1/search",
            headers,
            body.toRequestBody(JSON_MEDIA_TYPE),
        )
    }

    private fun parseSeriesList(response: Response): MangasPage {
        val result = response.parseAs<SearchResponseDto>()
        val mangas = result.items.map { it.toSManga() }
        val info = result.pageInfo
        val hasNextPage = (info?.current_page ?: 1) < (info?.num_pages ?: 1)
        return MangasPage(mangas, hasNextPage)
    }

    private fun RecordDto.toSManga(): SManga = SManga.create().apply {
        val s = slug ?: "comic"
        setUrlWithoutDomain("/comics/series/$s/$uuid")
        title = this@toSManga.title.orEmpty()
        description = this@toSManga.description
        thumbnail_url = base_asset_url?.let { "$it/box.jpg?w=600&auto=format,compress" }
    }

    // Details

    override fun mangaDetailsRequest(manga: SManga): Request {
        val uuid = (baseUrl + manga.url).toHttpUrl().pathSegments.last()
        return GET("$apiUrl/comics/1/series/$uuid/?trans=en", headers)
    }

    override fun getMangaUrl(manga: SManga): String = baseUrl + manga.url

    override fun mangaDetailsParse(response: Response): SManga {
        val series = response.parseAs<SeriesDto>()
        // Series responses carry no creator info; it only exists per issue.
        val issues = runCatching {
            client.newCall(seriesBooksRequest(series.uuid, 1)).execute().parseAs<SeriesBooksDto>().values
        }.getOrDefault(emptyList())
        return SManga.create().apply {
            title = series.title
            description = series.description
            thumbnail_url = series.base_asset_url?.let { "$it/box.jpg?w=600&auto=format,compress" }
            genre = series.tags
                .filter { it.categories.none { c -> c.equals("Data Driven", true) } }
                .map { it.name }
                .plus(series.age_rating?.takeIf { it.isNotBlank() })
                .filterNotNull()
                .joinToString()
            author = issues.creatorNames { it.authors }
            artist = issues.creatorNames { it.pencillers }
            status = SManga.UNKNOWN
            initialized = true
        }
    }

    // Chapters

    override fun chapterListRequest(manga: SManga): Request {
        val seriesUuid = (baseUrl + manga.url).toHttpUrl().pathSegments.last()
        return seriesBooksRequest(seriesUuid, 1)
    }

    private fun seriesBooksRequest(seriesUuid: String, page: Int): Request = GET("$apiUrl/comics/1/series/$seriesUuid/books/issue?page=$page&trans=en", headers)

    override fun chapterListParse(response: Response): List<SChapter> {
        var result = response.parseAs<SeriesBooksDto>()
        val segments = response.request.url.pathSegments
        val seriesUuid = segments.getOrNull(segments.indexOf("series") + 1)
        val books = result.values.toMutableList()
        var page = 1
        while (seriesUuid != null && page < result.num_pages) {
            page++
            result = client.newCall(seriesBooksRequest(seriesUuid, page)).execute()
                .parseAs<SeriesBooksDto>()
            if (result.values.isEmpty()) break
            books.addAll(result.values)
        }
        val indexed = books.mapIndexed { index, book -> book to book.toSChapter(index) }
        val visible = if (preferences.getBoolean(PREF_HIDE_LOCKED, false)) {
            refreshSessionCookie()
            indexed.filter { (book, _) -> canRead(book.uuid) }
        } else {
            indexed
        }
        return visible.map { it.second }.reversed()
    }

    private fun canRead(bookUuid: String): Boolean = try {
        val response = client.newCall(GET("$apiUrl/5/1/rights/comic/$bookUuid?trans=en", headers)).execute()
        val raw = response.use { it.body.string().trim() }
        response.code == 200 &&
            decodeJwtPayload(raw.removeSurrounding("\"")).parseAs<RightsDto>().rights.can_read
    } catch (_: Exception) {
        false
    }

    private fun SeriesBookDto.toSChapter(index: Int): SChapter = SChapter.create().apply {
        val s = slug ?: "comic"
        setUrlWithoutDomain("/comics/book/$s/$uuid")
        name = title ?: issue_number?.let { "Issue #$it" } ?: "Issue"
        chapter_number = issue_number?.toFloatOrNull() ?: (index + 1).toFloat()
        date_upload = dateFormatDay.tryParse(publish_date ?: release_date)
    }

    override fun getChapterUrl(chapter: SChapter): String = "$baseUrl${chapter.url}/c/reader"

    // Pages

    override fun pageListRequest(chapter: SChapter): Request {
        refreshSessionCookie()
        val uuid = (baseUrl + chapter.url).toHttpUrl().pathSegments.last()
        return GET("$apiUrl/5/1/rights/comic/$uuid?trans=en", headers)
    }

    // The browser calls set_cookie before every rights check; it turns the auth
    // token into a fresh HttpOnly session cookie.
    private fun refreshSessionCookie() {
        runCatching {
            client.newCall(
                POST("$apiUrl/users/set_cookie?trans=en", headers, "".toRequestBody()),
            ).execute().close()
        }
    }

    private fun readRights(response: Response): Pair<String, RightsDto> {
        val raw = response.use { it.body.string().trim() }
        if (response.code != 200) {
            throw IOException("Rights check failed (HTTP ${response.code}). Check your login in the source's Settings.")
        }
        val jwt = raw.removeSurrounding("\"")
        return jwt to decodeJwtPayload(jwt).parseAs<RightsDto>()
    }

    override fun pageListParse(response: Response): List<Page> {
        val (jwt, rights) = readRights(response)
        if (!rights.rights.can_read) {
            val who = if (rights.user_guid.isNullOrBlank()) {
                "${authErrorMessage()} [server sees you signed OUT; ${tokenState()}]"
            } else {
                "Signed in as a real account, but this issue isn't readable (needs an active subscription). [${tokenState()}]"
            }
            throw IOException(who)
        }

        val pageHeaders = headersBuilder()
            .set("x-auth-jwt", jwt)
            .build()

        // Ask for the HD manifest when the issue has one; fall back to SD.
        val qualities = if (rights.rights.hd_available) listOf("HD", "SD") else listOf("SD")
        var quality = qualities.first()
        var firstBody: String? = null
        for (q in qualities) {
            val res = client.newCall(downloadRequest(1, q, pageHeaders)).execute()
            if (res.isSuccessful) {
                firstBody = res.body.string()
                quality = q
                break
            }
            res.close()
        }
        firstBody ?: throw IOException("Could not load the page list for this issue.")

        val previews = mutableListOf<String>()
        var manifest = firstBody.parseAs<DownloadDto>()
        var pageNum = 1
        while (true) {
            manifest.images.mapNotNullTo(previews) { it.thumbnail_url }
            if (pageNum >= manifest.num_pages) break
            pageNum++
            manifest = client.newCall(downloadRequest(pageNum, quality, pageHeaders)).execute()
                .parseAs<DownloadDto>()
        }
        if (previews.isEmpty()) throw IOException("No pages found for this issue.")

        // Find the largest size the server will hand out for the preview images.
        val results = SIZE_VARIANTS.map { variant ->
            val url = variant.apply(previews.first())
            VariantResult(variant, url, measureImage(url))
        }
        // maxByOrNull keeps the earliest of equal sizes, so "as given" wins ties.
        val best = results
            .maxByOrNull { r -> r.size?.let { it.first.toLong() * it.second } ?: -1L }
            ?.takeIf { it.size != null }
            ?.variant
            ?: SIZE_VARIANTS.first()

        if (preferences.getBoolean(PREF_DEBUG, false)) {
            throw IOException(debugReport(firstBody, quality, rights.rights.hd_available, results, best))
        }

        return previews.mapIndexed { i, url -> Page(i, imageUrl = best.apply(url)) }
    }

    private fun downloadRequest(page: Int, quality: String, headers: Headers): Request = GET("$apiUrl/comics/1/book/download/?page=$page&quality=$quality&trans=en", headers)

    private class SizeVariant(val label: String, val apply: (String) -> String)

    private class VariantResult(val variant: SizeVariant, val url: String, val size: Pair<Int, Int>?)

    /** Returns width x height of the image at [url], or null if it didn't load as an image. */
    private fun measureImage(url: String): Pair<Int, Int>? = runCatching {
        client.newCall(imageRequest(Page(0, imageUrl = url))).execute().use { res ->
            if (!res.isSuccessful) return@use null
            val bytes = res.body.bytes()
            val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)
            if (opts.outWidth > 0 && opts.outHeight > 0) opts.outWidth to opts.outHeight else null
        }
    }.getOrNull()

    // Kept short so it fits in the app's error message.
    private fun debugReport(
        manifestBody: String,
        quality: String,
        hdAvailable: Boolean,
        results: List<VariantResult>,
        chosen: SizeVariant,
    ): String = buildString {
        append("DEBUG hd=$hdAvailable q=$quality. ")
        results.forEach { r ->
            append("${r.variant.label}: ${r.size?.let { "${it.first}x${it.second}" } ?: "fail"}; ")
        }
        append("using ${chosen.label}. ")
        results.firstOrNull()?.url?.toHttpUrl()?.let { u ->
            append("host ${u.host}, query keys: ${u.queryParameterNames.joinToString().ifEmpty { "none" }}. ")
        }
        runCatching {
            val img = Json.parseToJsonElement(manifestBody).jsonObject["images"]
                ?.jsonArray?.firstOrNull() as? JsonObject
            if (img != null) append("image keys: ${img.keys.joinToString()}")
        }
    }

    override fun imageRequest(page: Page): Request {
        val imageHeaders = super.headersBuilder()
            .set("Referer", "$baseUrl/")
            .build()
        return GET(page.imageUrl!!, imageHeaders)
    }

    override fun imageUrlParse(response: Response): String = throw UnsupportedOperationException()

    // Filters

    override fun getFilterList(): FilterList = FilterList(
        Filter.Header("Character & Imprint must match DCUI's exact name, e.g. Batman"),
        SortFilter(),
        EraFilter(),
        FormatFilter(),
        CharacterFilter(),
        ImprintFilter(),
    )

    private class SortOption(val name: String, val field: String, val direction: String)

    private class SortFilter : Filter.Select<String>("Sort by", SORTS.map { it.name }.toTypedArray()) {
        val selected: SortOption get() = SORTS[state]
    }

    private class EraFilter : Filter.Select<String>("Era", ERAS.map { it.first }.toTypedArray()) {
        val selectedValue: String get() = ERAS[state].second
    }

    private class FormatFilter : Filter.Select<String>("Format", FORMATS.map { it.first }.toTypedArray()) {
        val selectedValue: String get() = FORMATS[state].second
    }

    private class CharacterFilter : Filter.Text("Character")

    private class ImprintFilter : Filter.Text("Imprint")

    // Helpers

    private fun List<SeriesBookDto>.creatorNames(select: (SeriesBookDto) -> List<CreatorDto>): String? = flatMap(select).mapNotNull { it.name }.distinct().take(5).joinToString().ifEmpty { null }

    private fun decodeJwtPayload(jwt: String): String {
        val payload = jwt.split(".").getOrNull(1)
            ?: throw IOException("Invalid rights token")
        return String(Base64.decode(payload, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
    }

    private fun String.jsonStr(): String = buildString {
        append('"')
        this@jsonStr.forEach { c ->
            when (c) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> append(c)
            }
        }
        append('"')
    }

    private fun okhttp3.RequestBody?.bodyString(): String {
        this ?: return ""
        val buffer = okio.Buffer()
        writeTo(buffer)
        return buffer.readUtf8()
    }

    companion object {
        private const val CONSUMER_KEY = "DA59dtVXYLxajktV"
        private const val READER_HOST = "reader.dcuniverseinfinite.com"
        private const val PER_PAGE = 20
        private const val PREF_SESSION_COOKIE = "pref_session_cookie"
        private const val PREF_HIDE_LOCKED = "pref_hide_locked"
        private const val PREF_DEBUG = "debug_image_report"

        private val SIZE_VARIANTS = listOf(
            SizeVariant("as given") { it },
            SizeVariant("w=2400") { it.withQuery("w" to "2400", "h" to null) },
            SizeVariant("width=2400") { it.withQuery("width" to "2400", "height" to null) },
            SizeVariant("no size params") {
                it.withQuery("w" to null, "h" to null, "width" to null, "height" to null)
            },
        )

        private fun String.withQuery(vararg params: Pair<String, String?>): String {
            val builder = toHttpUrl().newBuilder()
            params.forEach { (k, v) ->
                if (v == null) builder.removeAllQueryParameters(k) else builder.setQueryParameter(k, v)
            }
            return builder.build().toString()
        }
        private const val LEGACY_PREF_EMAIL = "pref_email"
        private const val LEGACY_PREF_PASSWORD = "pref_password"
        private const val LEGACY_PREF_LOGIN_TOKEN = "pref_login_token"
        private val JSON_MEDIA_TYPE = "application/json;charset=UTF-8".toMediaType()

        private val SORTS = listOf(
            SortOption("Newest", "first_released", "desc"),
            SortOption("Oldest", "first_released", "asc"),
            SortOption("Title A-Z", "title", "asc"),
            SortOption("Title Z-A", "title", "desc"),
        )

        private val FORMATS = listOf(
            "All" to "",
            "DC GO! (vertical)" to "Vertical",
        )

        private val ERAS = listOf(
            "All" to "",
            "Golden Age" to "golden-age",
            "Silver Age" to "silver-age",
            "Bronze Age" to "bronze-age",
            "Modern Age" to "modern-age",
            "New 52" to "new-52",
            "Rebirth" to "rebirth",
        )
    }
}
